package agora

import (
	"time"
)

// Implementation based on https://github.com/AgoraIO/Tools/blob/master/DynamicKey/AgoraDynamicKey/go/src/RtmTokenBuilder/RtmTokenBuilder.go

/* RtmTokenBuilder class
 */

//BuildToken method
// appID: The App ID issued to you by Agora. Apply for a new App ID from
//        Agora Dashboard if it is missing from your kit. See Get an App ID.
// appCertificate:	Certificate of the application that you registered in
//                  the Agora Dashboard. See Get an App Certificate.
// userAccount: The user account.
// privilegeExpireTs: represented by the number of seconds elapsed since
//                    1/1/1970. If, for example, you want to access the
//                    Agora Service within 10 minutes after the token is
//                    generated, set expireTimestamp as the current
//                    timestamp + 600 (seconds)./
func BuildRTMToken(appID string, appCertificate string, userAccount string, privilegeExpiredTs time.Time) (string, error) {
	token := NewAccessTokenStrUID(appID, appCertificate, userAccount, "")
	token.AddPrivilege(PrivilegeLoginRtm, privilegeExpiredTs)
	return token.Build()
}
