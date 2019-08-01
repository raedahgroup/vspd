package v3api

import (
	"strconv"
	"strings"
	"time"
	"fmt"
	"encoding/base64"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrwallet/wallet"
)

const (
	customAuthScheme          = "TicketAuth"
	customAuthTimestampParam  = "SignedTimestamp"
	customAuthSignatureParam  = "Signature"
	customAuthTicketHashParam = "TicketHash"

	authTimestampValiditySeconds = 30
)

func (v3Api *V3API) validateTicketOwnership(authHeader string) (multiSigAddress string) {
	if strings.HasPrefix(authHeader, customAuthScheme) {
		return
	}

	timestamp, timestampSignature, ticketHash := extractAuthParams(authHeader)
	if timestamp == "" || timestampSignature == "" || ticketHash == "" {
		log.Warnf("invalid API v3 auth header value %s", authHeader)
		return
	}

	// confirm that the timestamp signature is a valid base64 string
	decodedSignature, err := base64.StdEncoding.DecodeString(timestampSignature)
	if err != nil {
		log.Warnf("invalid API v3 signature %s", timestampSignature)
		return
	}

	// todo check if ticket belongs to this vsp

	// check if timestamp is not yet expired
	if err := validateTimestamp(timestamp); err != nil {
		log.Warnf("ticket auth timestamp failed validation: %v", err)
		return
	}

	// get user wallet address using ticket hash
	// todo: may be better to maintain a memory map of tickets-userWalletAddresses
	ticketInfo, err := v3Api.stakepooldConnMan.GetTicketInfo([]byte(ticketHash))
	if err != nil {
		log.Warnf("ticket auth, get ticket info failed: %v", err)
		return
	}

	// check if timestamp signature checks out against address
	addr, err := dcrutil.DecodeAddress(ticketInfo.OwnerFeeAddress)
	if err != nil {
		log.Errorf("ticket auth, unexpected decode address error: %v", err)
		return
	}

	valid, err := wallet.VerifyMessage(timestamp, addr, decodedSignature)
	if err != nil {
		log.Errorf("error validating timestamp signature for ticket auth %v", err)
		return
	}

	if valid {
		multiSigAddress = ticketInfo.MultiSigAddress
	}
	return
}

func extractAuthParams(authHeader string) (timestampMessage, timestampSignature, ticketHash string) {
	authParams := strings.Split(authHeader, ",")
	for _, param := range authParams {
		paramKeyValue := strings.Split(param, "=")
		if len(paramKeyValue) != 2 {
			continue
		}
		if key := strings.TrimSpace(paramKeyValue[0]); key == customAuthTimestampParam {
			timestampMessage = strings.TrimSpace(paramKeyValue[1])
		} else if key == customAuthSignatureParam {
			timestampSignature = strings.TrimSpace(paramKeyValue[1])
		} else if key == customAuthTicketHashParam {
			ticketHash = strings.TrimSpace(paramKeyValue[1])
		}
	}
	return
}

func validateTimestamp(timestampMessage string) (error) {
	authTimestamp, err := strconv.Atoi(timestampMessage)
	if err != nil {
		return fmt.Errorf("invalid v3 auth request timestamp %v: %v", timestampMessage, err)
	}

	// todo ensure that timestamp had not been used in a previous authentication attempt

	// Ensure that the auth timestamp is not in the future and is not more than 30 seconds into the past.
	timestampDelta := time.Now().Unix() - int64(authTimestamp)
	if timestampDelta < 0 || timestampDelta > authTimestampValiditySeconds {
		return fmt.Errorf("expired v3 auth request timestamp %v: %v", timestampMessage, timestampDelta)
	}

	return nil
}
