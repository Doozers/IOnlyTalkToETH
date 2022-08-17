package main

import (
	"berty.tech/berty/v2/go/pkg/bertybot"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/Doozers/BasicPublicKeyEncryption/lib"
	"github.com/Doozers/ETH-Signature/ethsign"
)

type jsonAuth struct {
	Step int               `json:"step"`
	Data map[string]string `json:"data"`
}

func step0(ctx bertybot.Context, t jsonAuth) {
	if t.Data["ethPubkey"] == "" {
		ctx.ReplyString("error: missing ethPubKey")
		return
	}

	// to modify
	pubKey, err := os.ReadFile("public.key")
	if err != nil {
		ctx.ReplyString("error: " + err.Error())
		return
	}

	nonce := rand.Int()

	m, err := json.Marshal(jsonAuth{
		Step: 1,
		Data: map[string]string{
			"nonce": fmt.Sprintf("%d", nonce),
			"sig":   base64.StdEncoding.EncodeToString(lib.Sign((*[64]byte)(pubKey), []byte(fmt.Sprintf("%d%ssisi", nonce, t.Data["ethPubkey"])))),
		},
	})
	if err != nil {
		ctx.ReplyString("error: " + err.Error())
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(lib.Sign((*[64]byte)(pubKey), []byte(fmt.Sprintf("%d%ssisi", nonce, t.Data["ethPubkey"])))))
	ctx.ReplyString(string(m))
}

func step2(ctx bertybot.Context, t jsonAuth) {
	if t.Data["prev_nonce"] == "" || t.Data["prev_sig"] == "" || t.Data["ethPubkey"] == "" || t.Data["sig"] == "" || t.Data["hash"] == "" {
		ctx.ReplyString("error: missing arg")
		return
	}

	privKey, err := os.ReadFile("private.key")
	if err != nil {
		ctx.ReplyString("error: " + err.Error())
		return
	}

	prevSig, err := base64.StdEncoding.DecodeString(t.Data["prev_sig"])
	if err != nil {
		ctx.ReplyString("error: " + err.Error())
		return
	}

	res, ok := lib.Verify((*[32]byte)(privKey), prevSig)
	fmt.Println(string(res))
	if !ok || string(res) != t.Data["prev_nonce"]+t.Data["ethPubkey"]+"sisi" {
		ctx.ReplyString("error: invalid previous signature")
		return
	}

	switch t.Data["hash"] {
	case "text":
		ok, err = ethsign.Verify(t.Data["prev_nonce"]+t.Data["prev_sig"], t.Data["sig"], t.Data["ethPubkey"], ethsign.TextHash)
		break
	case "keccak256":
		ok, err = ethsign.Verify(t.Data["prev_nonce"]+t.Data["prev_sig"], t.Data["sig"], t.Data["ethPubkey"], ethsign.Keccak256)
		break
	}

	if ok {
		m, err := json.Marshal(jsonAuth{
			Step: 3,
			Data: map[string]string{
				"message": "sync accepted",
			},
		})
		if err != nil {
			ctx.ReplyString("error: " + err.Error())
			return
		}

		ctx.ReplyString(string(m))
		return
	}
	ctx.ReplyString("error: invalid signature")
}

func Auth(ctx bertybot.Context) {
	data := strings.Replace(ctx.UserMessage, "/verify-me ", "", 1)

	var t jsonAuth
	err := json.Unmarshal([]byte(data), &t)
	if err != nil {
		ctx.ReplyString("error: " + err.Error())
	}

	switch t.Step {
	case 0:
		step0(ctx, t)
		break
	case 2:
		step2(ctx, t)
		break
	default:
		ctx.ReplyString("error: unknown step")
	}
}
