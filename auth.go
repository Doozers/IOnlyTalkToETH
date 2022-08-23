package main

import (
	"berty.tech/berty/v2/go/pkg/bertybot"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"

	"github.com/Doozers/BasicPublicKeyEncryption/lib"
	"github.com/Doozers/ETH-Signature/ethsign"
)

type metaData struct {
	EthPubkey string `json:"pubkey,omitempty"`
	PrevNonce string `json:"prev_nonce,omitempty"`
	PrevSig   string `json:"prev_sig,omitempty"`
	Sig       string `json:"sig,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Message   string `json:"message,omitempty"`
	HashType  string `json:"hash_type,omitempty"`
}

type jsonAuth struct {
	Step int      `json:"step"`
	Data metaData `json:"data"`
}

func step0(t jsonAuth) (*jsonAuth, error) {
	if t.Data.EthPubkey == "" {
		return nil, errors.New("missing ethPubKey")
	}

	// hash(nonce+pubkey) and sign the hash
	nonce := rand.Int()
	proof := fmt.Sprintf("%d%ssisi", nonce, t.Data.EthPubkey)
	hash := sha256.Sum256([]byte(proof))
	sig := lib.Sign((*[64]byte)(PublicKey), hash[:])
	b64sig := base64.StdEncoding.EncodeToString(sig)
	data := jsonAuth{
		Step: 1,
		Data: metaData{
			Nonce:   fmt.Sprintf("%d", nonce),
			Sig:     b64sig,
			Message: "hash(Nonce+Sig) and sign the hash",
		},
	}

	// Here because if you are using berty mini you won't be able to see the full message (https://github.com/berty/berty/issues/4360)
	fmt.Println(data)

	return &data, nil
}

func step2(convPubkey string, t jsonAuth, authorizedList *[]string) (*jsonAuth, error) {
	if t.Data.PrevNonce == "" || t.Data.PrevSig == "" || t.Data.EthPubkey == "" || t.Data.Sig == "" || t.Data.HashType == "" {
		return nil, errors.New("missing data")
	}

	// verify the authenticity of the given previous signature
	prevSig, err := base64.StdEncoding.DecodeString(t.Data.PrevSig)
	if err != nil {
		return nil, err
	}

	res, ok := lib.Verify((*[32]byte)(PrivateKey), prevSig)

	// check if the signature is valid (is the user owner of the private key linked to the given public key)
	hash32 := sha256.Sum256([]byte(fmt.Sprintf("%d%ssisi", t.Data.PrevNonce, t.Data.EthPubkey+"sisi")))
	hash := hash32[:]
	if !ok || bytes.Equal(res, hash) {
		return nil, errors.New("invalid previous signature")
	}

	hash32_2 := sha256.Sum256([]byte(t.Data.PrevNonce + t.Data.PrevSig))
	hash2 := hash32_2[:]

	switch t.Data.HashType {
	case "text":
		ok, err = ethsign.Verify(fmt.Sprintf("%x", hash2), t.Data.Sig, t.Data.EthPubkey, ethsign.TextHash)
	case "keccak256":
		ok, err = ethsign.Verify(fmt.Sprintf("%x", hash2), t.Data.Sig, t.Data.EthPubkey, ethsign.Keccak256)
	}
	if err != nil {
		return nil, err
	}

	if ok {
		j := jsonAuth{
			Step: 3,
			Data: metaData{
				Message: "sync accepted",
			},
		}
		if err != nil {
			return nil, errors.New("error: " + err.Error())
		}

		// whitelist the conversation public key
		*authorizedList = append(*authorizedList, convPubkey)
		return &j, nil
	}
	return nil, errors.New("error: invalid sig")
}

func Auth(authorizedList *[]string) func(ctx bertybot.Context) {
	return func(ctx bertybot.Context) {
		data := strings.Replace(ctx.UserMessage, "/verify-me ", "", 1)

		var t jsonAuth
		err := json.Unmarshal([]byte(data), &t)
		if err != nil {
			ctx.ReplyString("error: " + err.Error())
		}

		var res *jsonAuth

		switch t.Step {
		case 0:
			res, err = step0(t)
			break
		case 2:
			res, err = step2(ctx.ConversationPK, t, authorizedList)
			break
		default:
			err = errors.New("error: invalid step")
		}

		if err != nil {
			ctx.ReplyString("error: " + err.Error())
		} else {
			s, err := json.Marshal(res)
			if err != nil {
				ctx.ReplyString("error: " + err.Error())
			} else {
				ctx.ReplyString(string(s))
			}
		}
	}
}

func Chat(authorizedList *[]string) func(ctx bertybot.Context) {
	return func(ctx bertybot.Context) {
		if ctx.IsReplay || !ctx.IsNew {
			return
		}

		auth := *authorizedList

		// check if the conversation is authorized
		for _, v := range auth {
			if v == ctx.ConversationPK {
				_ = ctx.ReplyString("I'm proud of you !")
				return
			}
		}
		_ = ctx.ReplyString("I only talk to ETH verified users, '//verify-me' to verify yourself.")
	}
}
