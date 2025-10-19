import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

class Settings:
    def __init__(self):
        self.environment = os.getenv("ENV", "dev")
        self.vault_uri = os.getenv("KEY_VAULT_URI")

        if self.vault_uri:
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=self.vault_uri, credential=credential)
            self.database_url = client.get_secret("POSTGRES-URI").value
            self.google_client_id = client.get_secret("GOOGLE-CLIENT-ID").value
            self.google_client_secret = client.get_secret("GOOGLE-CLIENT-SECRET").value
        else:
            self.database_url = os.getenv("POSTGRES_CONNECTION_STRING")
            self.google_client_id = os.getenv("GOOGLE_CLIENT_ID")
            self.google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET")

settings = Settings()
