package agora

import (
	"testing"
	"time"
)

func Test_RtcTokenBuilder(t *testing.T) {
	appID := "970CA35de60c44645bbae8a215061b33"
	appCertificate := "5CFd2fd1755d40ecb72977518be15d3b"
	channelName := "7d72365eb983485397e3e3f9d460bdda"
	uidZero := uint32(0)

	expiredTs := time.Unix(1446455471, 0)
	result, err := BuildRTCTokenWithUID(appID, appCertificate, channelName, uidZero, RoleSubscriber, expiredTs)

	if err != nil {
		t.Error(err)
	}

	token, err := NewAccessTokenFromString(result)
	if err != nil {
		t.Error(err)
	}

	if token.message[PrivilegeJoinChannel] != uint32(expiredTs.Unix()) {
		t.Error("no kJoinChannel ts")
	}

	if token.message[PrivilegePublishVideoStream] != 0 {
		t.Error("should not have publish video stream privilege")
	}
}
