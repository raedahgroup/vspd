package controllers

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/decred/dcrstakepool/models"
	"github.com/decred/dcrstakepool/poolapi"
	"github.com/zenazn/goji/web"
	"google.golang.org/grpc/codes"
	"net/http"
	"strconv"
)

// APIVotingPost is the API version of VotingPost
func (controller *MainController) APIb(c web.C, r *http.Request) ([]string, codes.Code, string, error) {
	dbMap := controller.GetDbMap(c)

	if c.Env["APIUserID"] == nil {
		return nil, codes.Unauthenticated, "voting error", errors.New("invalid api token")
	}

	user, _ := models.GetUserById(dbMap, c.Env["APIUserID"].(int64))
	oldVoteBits := user.VoteBits

	vb := r.FormValue("VoteBits")
	vbi, err := strconv.Atoi(vb)
	if err != nil {
		return nil, codes.InvalidArgument, "voting error", errors.New("unable to convert votebits to uint16")
	}
	userVoteBits := uint16(vbi)

	if !controller.IsValidVoteBits(userVoteBits) {
		return nil, codes.InvalidArgument, "voting error", errors.New("votebits invalid for current agendas")
	}

	user, err = helpers.UpdateVoteBitsByID(dbMap, user.Id, userVoteBits)
	if err != nil {
		return nil, codes.Internal, "voting error", errors.New("failed to update voting prefs in database")
	}

	if uint16(oldVoteBits) != userVoteBits {
		controller.StakepooldUpdateUsers(dbMap)
	}

	log.Infof("updated voteBits for user %d from %d to %d",
		user.Id, oldVoteBits, userVoteBits)

	return nil, codes.OK, "successfully updated voting preferences", nil
}

const TicketChallengeByteSize = 32

// RegisterPost form submit route. Registers new user or shows Registration route with
// appropriate messages set in session.
func (controller *MainController) TicketChallenge(c web.C, r *http.Request) (*poolapi.Stats, codes.Code, string, error) {
	randomBytes := make([]byte, TicketChallengeByteSize)
	_, err := rand.Read(randomBytes)
	if err != nil {
		// todo log error and return
	}

	challenge := base64.URLEncoding.EncodeToString(randomBytes)
	return nil, codes.OK, "challenge expires in", nil
}
