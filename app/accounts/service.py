def create_invitation(user, email: str):
    if user.account_role != "owner":
        raise PermissionError("Solo owner puede invitar")

    # lógica
    # repositorio
    # auditoría
    # email
