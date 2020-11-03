import logging
from flask import flash, redirect, url_for, Blueprint, request
from redash import settings
from redash.authentication import create_and_login_user, logout_and_redirect_to_index
from redash.authentication.org_resolving import current_org
from redash.handlers.base import org_scoped_rule
from redash.utils import mustache_render
from redash import redis_connection
from requests_oauthlib import OAuth2Session
import jwt
import os
import requests
import pyodbc
import struct

USER_REFRESH_TOKEN = "users:refresh_token"

logger = logging.getLogger("openid_auth")
blueprint = Blueprint("openid_auth", __name__)
# inline_metadata_template = """<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor entityID="{{entity_id}}" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{{x509_cert}}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{{sso_url}}"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{{sso_url}}"/></md:IDPSSODescriptor></md:EntityDescriptor>"""


def get_oauth(org, redirect_uri, scope = None):
    """
    Return oauth configuration.

    The configuration is a hash for use by oauth2.config.Config
    """
    client_id = org.get_setting("auth_openid_client_id")

    if scope==None:
        scope = org.get_setting("auth_openid_scope")
        #scope = "openid profile offline_access"

    os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"]="True"

    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri,
                          scope=scope)
    return oauth

@blueprint.route(org_scoped_rule("/openid/callback"), methods=["GET"])
def idp_initiated(org_slug=None):

    oauth = get_oauth(current_org, request.host_url.strip('/') + "/openid/callback")

    token_url = current_org.get_setting("auth_openid_token_url")
    #token_url = 'https://login.microsoftonline.com/neurodev.onmicrosoft.com/oauth2/v2.0/token'

    client_secret = current_org.get_setting("auth_openid_client_secret")

    authorization_response_url = request.url
    if 'http://localhost' in request.host_url.lower():
        authorization_response_url = authorization_response_url.replace('http:','https:')

    token = oauth.fetch_token(
            token_url,
            authorization_response=request.url.replace('http:','https:'),
            client_secret=client_secret)

    claims = jwt.decode(token['access_token'], verify=False)

    name_claim = current_org.get_setting("auth_openid_name_claim")
    #name_claim = 'name'
    name = claims[name_claim]

    email_claim = current_org.get_setting("auth_openid_email_claim")
    #email_claim = 'upn'
    email = claims[email_claim]

    user = create_and_login_user(current_org, name, email)
    if user is None:
        return logout_and_redirect_to_index()

    if "RedashGroups" in claims:
        group_names = claims["RedashGroups"]
        user.update_group_assignments(group_names)

    redis_connection.hset(USER_REFRESH_TOKEN,user.id,token['refresh_token'])

    url = url_for("redash.index", org_slug=org_slug)

    return redirect(url)

@blueprint.route(org_scoped_rule("/openid/login"))
def sp_initiated(org_slug=None):

    if not current_org.get_setting("auth_openid_login_enabled"):
        logger.error("OPENID Login is not enabled")
        return redirect(url_for("redash.index", org_slug=org_slug))

    oauth = get_oauth(current_org, request.host_url.strip('/') + "/openid/callback")

    auth_url = current_org.get_setting("auth_openid_auth_url")
    # auth_url = 'https://login.microsoftonline.com/neurodev.onmicrosoft.com/oauth2/v2.0/authorize'
    authorization_url, state = oauth.authorization_url(
        auth_url,)
        # access_type="offline", prompt="select_account")
    
    response = redirect(authorization_url, code=302)

    # NOTE:
    #   I realize I _technically_ don't need to set Cache-Control or Pragma:
    #     https://stackoverflow.com/a/5494469
    #   However, Section 3.2.3.2 of the SAML spec suggests they are set:
    #     http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
    #   We set those headers here as a "belt and suspenders" approach,
    #   since enterprise environments don't always conform to RFCs
    response.headers["Cache-Control"] = "no-cache, no-store"
    response.headers["Pragma"] = "no-cache"
    return response