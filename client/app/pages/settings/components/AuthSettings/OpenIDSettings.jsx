import React from "react";
import Form from "antd/lib/form";
import Input from "antd/lib/input";
import Radio from "antd/lib/radio";
import DynamicComponent from "@/components/DynamicComponent";
import { SettingsEditorPropTypes, SettingsEditorDefaultProps } from "../prop-types";

export default function OpenIDSettings(props) {
  const { values, onChange } = props;

  const onChangeEnabledStatus = e => {
    const updates = { auth_openid_login_enabled: !!e.target.value };
    onChange(updates);
  };

  return (
    <DynamicComponent name="OrganizationSettings.OpenIDSettings" {...props}>
      <h4>OpenID</h4>
      <Form.Item label="OpenID Enabled">
        <Radio.Group
          onChange={onChangeEnabledStatus}
          value={values.auth_openid_login_enabled}>
          <Radio value={false}>Disabled</Radio>
          <Radio value={true}>Enabled</Radio>
        </Radio.Group>
      </Form.Item>
      {values.auth_openid_login_enabled && (
        <>
          <Form.Item label="OpenID Auth URL">
            <Input
              value={values.auth_openid_auth_url}
              onChange={e => onChange({ auth_openid_auth_url: e.target.value })}
            />
          </Form.Item>
          <Form.Item label="OpenID Token URL">
            <Input
              value={values.auth_openid_token_url}
              onChange={e => onChange({ auth_openid_token_url: e.target.value })}
            />
          </Form.Item>
          <Form.Item label="OpenID Client ID">
            <Input
              value={values.auth_openid_client_id}
              onChange={e => onChange({ auth_openid_client_id: e.target.value })}
            />
          </Form.Item>
          <Form.Item label="OpenID Client Secret">
            <Input
              value={values.auth_openid_client_secret}
              onChange={e => onChange({ auth_openid_client_secret: e.target.value })}
            />
          </Form.Item>
          <Form.Item label="OpenID Scope (openid profile offline_access)">
            <Input
              value={values.auth_openid_scope}
              onChange={e => onChange({ auth_openid_scope: e.target.value })}
            />
          </Form.Item>
          <Form.Item label="OpenID Name Claim (name)">
            <Input
              value={values.auth_openid_name_claim}
              onChange={e => onChange({ auth_openid_name_claim: e.target.value })}
            />
          </Form.Item>
          <Form.Item label="OpenID Email Claim (email)">
            <Input
              value={values.auth_openid_email_claim}
              onChange={e => onChange({ auth_openid_email_claim: e.target.value })}
            />
          </Form.Item>
        </>
      )}
    </DynamicComponent>
  );
}

OpenIDSettings.propTypes = SettingsEditorPropTypes;

OpenIDSettings.defaultProps = SettingsEditorDefaultProps;