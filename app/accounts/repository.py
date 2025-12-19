def get_plan_info(conn, account_id: int):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT plan_type FROM accounts WHERE id = %s",
            (account_id,),
        )
        plan = cur.fetchone()

        cur.execute(
            "SELECT COUNT(*) FROM account_members WHERE account_id = %s",
            (account_id,),
        )
        members = cur.fetchone()[0]

    return plan[0] if plan else "free", members
