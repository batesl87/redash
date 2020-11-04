import logging
import sys
import uuid
import requests
import struct
#testing
import traceback
import json
#testing

from redash.query_runner import *
from redash.query_runner.mssql import types_map
from redash.utils import json_dumps, json_loads
from redash import redis_connection
from redash import models

USER_REFRESH_TOKEN = "users:refresh_token"

logger = logging.getLogger(__name__)

try:
    import pyodbc

    enabled = True
except ImportError:
    enabled = False


class SQLServerODBC(BaseSQLQueryRunner):
    should_annotate_query = False
    noop_query = "SELECT 1"

    @classmethod
    def configuration_schema(cls):
        return {
            "type": "object",
            "properties": {
                "server": {"type": "string"},
                "port": {"type": "number", "default": 1433},
                "user": {"type": "string"},
                "password": {"type": "string"},
                "db": {"type": "string", "title": "Database Name"},
                "charset": {
                    "type": "string",
                    "default": "UTF-8",
                    "title": "Character Set",
                },
                "use_aad": {"type": "boolean", "title": "Use Azure AD", "default": False,},
                "use_ssl": {"type": "boolean", "title": "Use SSL", "default": False,},
                "verify_ssl": {
                    "type": "boolean",
                    "title": "Verify SSL certificate",
                    "default": True,
                },
            },
            "order": [
                "server",
                "port",
                "user",
                "password",
                "db",
                "charset",
                "use_ssl",
                "verify_ssl",
                "use_aad",
            ],
            "required": ["server", "db"],
            "secret": ["password"],
            "extra_options": ["verify_ssl", "use_ssl"],
        }

    @classmethod
    def enabled(cls):
        return enabled

    @classmethod
    def name(cls):
        return "Microsoft SQL Server (ODBC)"

    @classmethod
    def type(cls):
        return "mssql_odbc"

    def _get_tables(self, schema, user):
        query = """
        SELECT table_schema, table_name, column_name
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE table_schema NOT IN ('guest','INFORMATION_SCHEMA','sys','db_owner','db_accessadmin'
                                  ,'db_securityadmin','db_ddladmin','db_backupoperator','db_datareader'
                                  ,'db_datawriter','db_denydatareader','db_denydatawriter'
                                  );
        """
        results, error = self.run_query(query, user)

        if error is not None:
            raise Exception("Failed getting schema.")

        results = json_loads(results)

        for row in results["rows"]:
            if row["table_schema"] != self.configuration["db"]:
                table_name = "{}.{}".format(row["table_schema"], row["table_name"])
            else:
                table_name = row["table_name"]

            if table_name not in schema:
                schema[table_name] = {"name": table_name, "columns": []}

            schema[table_name]["columns"].append(row["column_name"])

        return list(schema.values())

    def run_query(self, query, user):
        connection = None

        try:
            if not self.configuration.get("use_aad", False):
                server = self.configuration.get("server")
                user_name = self.configuration.get("user", "")
                password = self.configuration.get("password", "")
                db = self.configuration["db"]
                port = self.configuration.get("port", 1433)
                charset = self.configuration.get("charset", "UTF-8")

                connection_string_fmt = "DRIVER={{ODBC Driver 17 for SQL Server}};PORT={};SERVER={};DATABASE={};UID={};PWD={}"
                connection_string = connection_string_fmt.format(
                    port, server, db, user_name, password
                )

                if self.configuration.get("use_ssl", False):
                    connection_string += ";Encrypt=YES"

                    if not self.configuration.get("verify_ssl"):
                        connection_string += ";TrustServerCertificate=YES"

                connection = pyodbc.connect(connection_string)
            else:
                
                current_org = models.Organization.get_by_id(user.get_org_id())

                server = self.configuration.get("server")
                db = self.configuration["db"]
                port = self.configuration.get("port", 1433)

                connection_string_fmt = "DRIVER={{ODBC Driver 17 for SQL Server}};PORT={};SERVER={};DATABASE={}"
                connection_string = connection_string_fmt.format(
                    port, server, db
                )

                if self.configuration.get("use_ssl", False):
                    connection_string += ";Encrypt=YES"

                    if not self.configuration.get("verify_ssl"):
                        connection_string += ";TrustServerCertificate=YES"

                
                token_url = current_org.get_setting("auth_openid_token_url")
                # token_url = 'https://login.microsoftonline.com/neurodev.onmicrosoft.com/oauth2/v2.0/token'
                
                client_id = current_org.get_setting("auth_openid_client_id")
                
                client_secret = current_org.get_setting("auth_openid_client_secret")

                refresh_token = redis_connection.hget(USER_REFRESH_TOKEN,user.id)

                scoped_token_response =  requests.post(token_url,data={'client_id':client_id,'client_secret':client_secret,'grant_type':'refresh_token','scope':'https://database.windows.net//.default','refresh_token':refresh_token})

                scoped_access_token = None
                if scoped_token_response.status_code>=200 and scoped_token_response.status_code<300:
                    scoped_access_token = scoped_token_response.json()['access_token']
                
                tokenb = bytes(scoped_access_token, "UTF-8")

                exptoken = b''
                for i in tokenb:
                    exptoken += bytes({i})
                    exptoken += bytes(1)
                tokenstruct = struct.pack("=i", len(exptoken)) + exptoken
                tokenstruct

                SQL_COPT_SS_ACCESS_TOKEN = 1256
                connection = pyodbc.connect(connection_string, attrs_before = { SQL_COPT_SS_ACCESS_TOKEN:tokenstruct })

            cursor = connection.cursor()
            logger.debug("SQLServerODBC running query: %s", query)
            cursor.execute(query)
            data = cursor.fetchall()

            if cursor.description is not None:
                columns = self.fetch_columns(
                    [(i[0], types_map.get(i[1], None)) for i in cursor.description]
                )
                rows = [
                    dict(zip((column["name"] for column in columns), row))
                    for row in data
                ]

                data = {"columns": columns, "rows": rows}
                json_data = json_dumps(data)
                error = None
            else:
                error = "No data was returned."
                json_data = None

            cursor.close()
        except pyodbc.Error as e:
            try:
                # Query errors are at `args[1]`
                error = e.args[1]
            except IndexError:
                # Connection errors are `args[0][1]`
                error = e.args[0][1]
            json_data = None
        except (KeyboardInterrupt, JobTimeoutException):
            connection.cancel()
            raise
        finally:
            if connection:
                connection.close()

        return json_data, error


register(SQLServerODBC)