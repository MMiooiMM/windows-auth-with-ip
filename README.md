# windows-auth-with-ip

## windowsauth 專案

用於發放 token, token 包含 ip, windows username, 過期時間等資訊。

## windowsauth.ap 專案

用於測試 token 是否有效，測試內容為：

1. 日期是否有效。
2. 簽發人是否一致。
3. ip 是否一致。

並能透過 User.Identity.Name 取得 windows username。
