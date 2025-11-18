# IDM (Identity Manager) Guidelines

Allows to store credentials per user. Every user can register themself as administrator. Then it becomes general profile. On behalf of that profile it would be possible to keep all necessary information required to authenticate with other providers. Such as Google with required fields: `ClientId` and `ClientSecret`.

toDO: `ClientId` is random generated unique string.

For the clarity it worth to mention that administrator can have several logins over google, microsoft, etc.

Every administrator can have logins that can have their profiles. Every profile allows to use login schemes enabled by administrator.

## Registered users/administrators list

Displays already created administrators. If user is administrator all users are available. If user is not administrator. They can see only themself. Just one line.

## Signup/Login providers list per user/administrator

Every user has a list of providers. Keeps all necessary information to manage various authentication providers.

## Roles and Permissions

| Resource | Permission   | list | add | details | write | remove |
| -------- | ------------ | ---- | --- | ------- | ----- | ------ |
| users    | list_users   | 1    |     | 1       |       |        |
| users    | create_users |      | 1   |         |       |        |
| users    | edit_users   |      |     | 1       | 1     |        |
| users    | delete_users |      |     | 1       |       | 1      |

## Users permissions and roles table

| User            | Resource | Permission     |
| --------------- | -------- | -------------- |
| User1 - manager | users    | list / details |
| User2 - editor  | users    | detais / write |

dd
