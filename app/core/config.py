import os
from typing import Optional

from azure.identity import DefaultAzureCredential # pyright: ignore[reportMissingImports]
from azure.keyvault.secrets import SecretClient # pyright: ignore[reportMissingImports]

from dotenv import load_dotenv
load_dotenv()

class Settings:
    def __init__(self):
        self.environment = os.getenv("ENV", "dev")
        self.vault_uri = os.getenv("KEY_VAULT_URI")
        self.backend_url = os.getenv("BACKEND_URL", "http://localhost:8000")

        self.database_url: Optional[str] = None
        self.google_client_id: Optional[str] = None
        self.google_client_secret: Optional[str] = None
        self.meta_app_id: Optional[str] = None
        self.meta_app_secret: Optional[str] = None
        self.google_ads_client_id: Optional[str] = None
        self.google_ads_client_secret: Optional[str] = None
        self.google_ads_developer_token: Optional[str] = None
        self.google_ads_login_mcc_id: Optional[str] = None
        self.tiktok_client_key: Optional[str] = None
        self.tiktok_client_secret: Optional[str] = None
        self.linkedin_client_id: Optional[str] = None
        self.linkedin_client_secret: Optional[str] = None
        self.jwt_secret: Optional[str] = None
        self.secret_key: Optional[str] = None
        self.token_encryption_key: Optional[str] = None
        self.session_cookie_name: str = os.getenv("SESSION_COOKIE_NAME", "mm_session")
        self.session_cookie_domain: Optional[str] = os.getenv(
            "SESSION_COOKIE_DOMAIN", ".azurewebsites.net"
        )
        self.session_cookie_samesite: str = os.getenv(
            "SESSION_COOKIE_SAMESITE", "lax"
        ).lower()
        self.session_cookie_secure: bool = (
            os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
        )

        if self.vault_uri:
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=self.vault_uri, credential=credential)

            self.database_url = self._get_secret(client, "POSTGRES-URI")
            self.google_client_id = self._get_secret(
                client, "GOOGLE-CLIENT-ID", env_fallback="GOOGLE_CLIENT_ID"
            )
            self.google_client_secret = self._get_secret(
                client, "GOOGLE-CLIENT-SECRET", env_fallback="GOOGLE_CLIENT_SECRET"
            )
            self.jwt_secret = self._get_secret(
                client, "JWT-SECRET-KEY", env_fallback="JWT_SECRET_KEY", default="default_jwt_secret"
            )
            self.meta_app_id = self._get_secret(
                client, "META-APP-ID", env_fallback="META_APP_ID"
            )
            self.meta_app_secret = self._get_secret(
                client, "META-APP-SECRET", env_fallback="META_APP_SECRET"
            )
            self.google_ads_client_id = self._get_secret(
                client, "GOOGLE-ADS-CLIENT-ID", env_fallback="GOOGLE_ADS_CLIENT_ID"
            )
            self.google_ads_client_secret = self._get_secret(
                client,
                "GOOGLE-ADS-CLIENT-SECRET",
                env_fallback="GOOGLE_ADS_CLIENT_SECRET",
            )
            self.google_ads_developer_token = self._get_secret(
                client,
                "GOOGLE-ADS-DEVELOPER-TOKEN",
                env_fallback="GOOGLE_ADS_DEVELOPER_TOKEN",
            )
            self.google_ads_login_mcc_id = self._get_secret(
                client,
                "GOOGLE-ADS-LOGIN-MCC-ID",
                env_fallback="GOOGLE_ADS_LOGIN_MCC_ID",
            )
            self.tiktok_client_key = self._get_secret(
                client, "TIKTOK-CLIENT-KEY", env_fallback="TIKTOK_CLIENT_KEY"
            )
            self.tiktok_client_secret = self._get_secret(
                client,
                "TIKTOK-CLIENT-SECRET",
                env_fallback="TIKTOK_CLIENT_SECRET",
            )
            self.linkedin_client_id = self._get_secret(
                client, "LINKEDIN-CLIENT-ID", env_fallback="LINKEDIN_CLIENT_ID"
            )
            self.linkedin_client_secret = self._get_secret(
                client,
                "LINKEDIN-CLIENT-SECRET",
                env_fallback="LINKEDIN_CLIENT_SECRET",
            )
            self.token_encryption_key = self._get_secret(
                client,
                "TOKEN-ENCRYPTION-KEY",
                env_fallback="TOKEN_ENCRYPTION_KEY",
            )
            self.secret_key = self.jwt_secret
        else:
            self.database_url = os.getenv("POSTGRES_CONNECTION_STRING")
            self.google_client_id = os.getenv("GOOGLE_CLIENT_ID")
            self.google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
            self.jwt_secret = os.getenv("JWT_SECRET_KEY", "default_jwt_secret")
            self.meta_app_id = os.getenv("META_APP_ID")
            self.meta_app_secret = os.getenv("META_APP_SECRET")
            self.google_ads_client_id = os.getenv("GOOGLE_ADS_CLIENT_ID")
            self.google_ads_client_secret = os.getenv("GOOGLE_ADS_CLIENT_SECRET")
            self.google_ads_developer_token = os.getenv("GOOGLE_ADS_DEVELOPER_TOKEN")
            self.google_ads_login_mcc_id = os.getenv("GOOGLE_ADS_LOGIN_MCC_ID")
            self.tiktok_client_key = os.getenv("TIKTOK_CLIENT_KEY")
            self.tiktok_client_secret = os.getenv("TIKTOK_CLIENT_SECRET")
            self.linkedin_client_id = os.getenv("LINKEDIN_CLIENT_ID")
            self.linkedin_client_secret = os.getenv("LINKEDIN_CLIENT_SECRET")
            self.token_encryption_key = os.getenv("TOKEN_ENCRYPTION_KEY")
            self.secret_key = self.jwt_secret

        if not self.database_url:
            raise RuntimeError("Database URL is not configured")

    def _get_secret(
        self,
        client: SecretClient,
        name: str,
        *,
        env_fallback: Optional[str] = None,
        default: Optional[str] = None,
    ) -> Optional[str]:
        try:
            return client.get_secret(name).value
        except Exception:
            if env_fallback:
                value = os.getenv(env_fallback)
                if value:
                    return value
            return default


settings = Settings()
