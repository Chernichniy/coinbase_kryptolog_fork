package main

import (
	"os"
	"fyne.io/fyne/v2/widget"
	"github.com/btcsuite/btcd/btcec"
	"math/big"
	"fyne.io/fyne/v2/container"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"fmt"
	"fyne.io/fyne/v2/app"
	"github.com/coinbase/kryptology/pkg/paillier"
	"encoding/hex"
	"fyne.io/fyne/v2"
	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/dealer"
	"crypto/sha256"
	"time"
	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/participant"
	"crypto/ecdsa"
	"github.com/dustinxie/ecc"
	"strconv"
)

var (
	numbersForTesting = []*big.Int{
		B10("186141419611617071752010179586510154515933389116254425631491755419216243670159714804545944298892950871169229878325987039840135057969555324774918895952900547869933648175107076399993833724447909579697857041081987997463765989497319509683575289675966710007879762972723174353568113668226442698275449371212397561567"),
		B10("94210786053667323206442523040419729883258172350738703980637961803118626748668924192069593010365236618255120977661397310932923345291377692570649198560048403943687994859423283474169530971418656709749020402756179383990602363122039939937953514870699284906666247063852187255623958659551404494107714695311474384687"),
		B10("62028909880050184794454820320289487394141550306616974968340908736543032782344593292214952852576535830823991093496498970213686040280098908204236051130358424961175634703281821899530101130244725435470475135483879784963475148975313832483400747421265545413510460046067002322131902159892876739088034507063542087523"),
		B10("321804071508183671133831207712462079740282619152225438240259877528712344129467977098976100894625335474509551113902455258582802291330071887726188174124352664849954838358973904505681968878957681630941310372231688127901147200937955329324769631743029415035218057960201863908173045670622969475867077447909836936523"),
		B10("52495647838749571441531580865340679598533348873590977282663145916368795913408897399822291638579504238082829052094508345857857144973446573810004060341650816108578548997792700057865473467391946766537119012441105169305106247003867011741811274367120479722991749924616247396514197345075177297436299446651331187067"),
		B10("118753381771703394804894143450628876988609300829627946826004421079000316402854210786451078221445575185505001470635997217855372731401976507648597119694813440063429052266569380936671291883364036649087788968029662592370202444662489071262833666489940296758935970249316300642591963940296755031586580445184253416139"),
	}
	paramForDealer = &dealer.ProofParams{
		N:  B10("135817986946410153263607521492868157288929876347703239389804036854326452848342067707805833332721355089496671444901101084429868705550525577068432132709786157994652561102559125256427177197007418406633665154772412807319781659630513167839812152507439439445572264448924538846645935065905728327076331348468251587961"),
		H1: B10("130372793360787914947629694846841279927281520987029701609177523587189885120190605946568222485341643012763305061268138793179515860485547361500345083617939280336315872961605437911597699438598556875524679018909165548046362772751058504008161659270331468227764192850055032058007664070200355866555886402826731196521"),
		H2: B10("44244046835929503435200723089247234648450309906417041731862368762294548874401406999952605461193318451278897748111402857920811242015075045913904246368542432908791195758912278843108225743582704689703680577207804641185952235173475863508072754204128218500376538767731592009803034641269409627751217232043111126391"),
	}
	Verifier = func(pubKey *curves.EcPoint, hash []byte, sig *curves.EcdsaSignature) bool {
		formPk := &btcec.PublicKey{
			Curve: btcec.S256(),
			X:     pubKey.X,
			Y:     pubKey.Y,
		}
		formSig := btcec.Signature{
			R: sig.R,
			S: sig.S,
		}
		return formSig.Verify(hash, formPk)
	}

	secret   *big.Int
	signText string

	participants uint32
	threshold    uint32

	pkX    *big.Int
	pkY    *big.Int
	share1 []byte
	share2 []byte

	sigR *big.Int
	sigS *big.Int

	timeStr = ""
)

// String -> bigInt
func B10(s string) *big.Int {
	x, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("Неможливо дістати big.Int з string")
	}
	return x
}

func createArrayOfPrimes(counter int) []struct{ p, q *big.Int } {
	arrayOfPrimes := make([]struct{ p, q *big.Int }, 0, counter)
	for len(arrayOfPrimes) < counter {
		for i := 0; i < len(numbersForTesting) && len(arrayOfPrimes) < counter; i++ {
			for j := 0; j < len(numbersForTesting) && len(arrayOfPrimes) < counter; j++ {
				if i == j {
					continue
				}
				keysOfPrimeValues := struct {
					p, q *big.Int
				}{
					numbersForTesting[i], numbersForTesting[j],
				}
				arrayOfPrimes = append(arrayOfPrimes, keysOfPrimeValues)
			}
		}
	}
	return arrayOfPrimes
}

func takeParameters(message *string, t, n *uint32) {
	counter := len(os.Args[1:])

	if counter > 0 {
		*message = os.Args[1]

	}
	if counter > 1 {
		value, _ := strconv.Atoi(os.Args[2])
		*t = uint32(value)
	}
	if counter > 2 {
		value, _ := strconv.Atoi(os.Args[3])
		*n = uint32(value)
	}

}

func start() bool {

	start := time.Now()
	thresholdNum := uint32(2)
	participantsNum := uint32(3)
	message := "Це шо, дипломна робота?"

	messageByte := []byte(message)
	messageHash := sha256.Sum256(messageByte)

	takeParameters(&message, &thresholdNum, &participantsNum)

	curveK256 := btcec.S256()

	shareSecret, _ := dealer.NewSecret(curveK256)

	privatKey, mapOfSharingParts, _ := dealer.NewDealerShares(curveK256, thresholdNum, participantsNum, shareSecret)

	fmt.Printf("Повідомлення: %s\n", message)
	signText = message

	fmt.Printf("Схема порогового підпису: Любі %d з %d\n", thresholdNum, participantsNum)
	participants = participantsNum
	threshold = thresholdNum

	fmt.Printf("Випадковий секрет: (%x)\n\n", shareSecret)
	secret = shareSecret
	fmt.Printf("Публічний ключ: (%s %s)\n\n", privatKey.X, privatKey.Y)

	pkX = privatKey.X
	pkY = privatKey.Y

	for len(mapOfSharingParts) > int(thresholdNum) {
		delete(mapOfSharingParts, uint32(len(mapOfSharingParts)))
	}
	pubmapOfSharingParts, _ := dealer.PreparePublicShares(mapOfSharingParts)
	mapOfKeys := make(map[uint32]*paillier.SecretKey, thresholdNum)
	mapOfPublicKeys := make(map[uint32]*paillier.PublicKey, thresholdNum)
	arrayOfPrimesForKey := createArrayOfPrimes(int(thresholdNum))
	for i := range mapOfSharingParts {
		mapOfKeys[i], _ = paillier.NewSecretKey(arrayOfPrimesForKey[i-1].p, arrayOfPrimesForKey[i-1].q)
		mapOfPublicKeys[i] = &mapOfKeys[i].PublicKey
		fmt.Printf("Частки секрету: %x\n", mapOfSharingParts[i].Bytes())
	}
	share1 = mapOfSharingParts[1].Bytes()
	share2 = mapOfSharingParts[2].Bytes()

	proofParams := &dealer.TrustedDealerKeyGenType{
		ProofParams: paramForDealer,
	}

	mapOfSignersParam := make(map[uint32]*participant.Signer, thresholdNum)
	for i, k := range mapOfKeys {
		p := participant.Participant{*mapOfSharingParts[i], k}

		mapOfSignersParam[i], _ = p.PrepareToSign(privatKey, Verifier, curveK256, proofParams, pubmapOfSharingParts, mapOfPublicKeys)
	}
	// Фази створення підпису
	// Фаза 1
	var err error
	outputOfEachSignerMap := make(map[uint32]*participant.Round1Bcast, thresholdNum)
	for i, s := range mapOfSignersParam {
		outputOfEachSignerMap[i], _, err = s.SignRound1()
		if err != nil {
			return false
		}
	}

	// Фаза 2
	peer2peerCommunicationMap := make(map[uint32]map[uint32]*participant.P2PSend)
	for i, s := range mapOfSignersParam {
		inputMap := make(map[uint32]*participant.Round1Bcast, thresholdNum-1)
		for j := range mapOfSignersParam {
			if i == j {
				continue
			}
			inputMap[j] = outputOfEachSignerMap[j]
		}
		peer2peerCommunicationMap[i], err = s.SignRound2(inputMap, nil)
		if err != nil {
			return false
		}
	}

	// Фаза 3
	round3BroadcastMap := make(map[uint32]*participant.Round3Bcast, thresholdNum)
	for i, s := range mapOfSignersParam {
		inputMap := make(map[uint32]*participant.P2PSend, thresholdNum-1)
		for j := range mapOfSignersParam {
			if i == j {
				continue
			}
			inputMap[j] = peer2peerCommunicationMap[j][i]
		}
		round3BroadcastMap[i], err = s.SignRound3(inputMap)
		if err != nil {
			return false
		}
	}

	// Фаза 4
	round4BroadcastMap := make(map[uint32]*participant.Round4Bcast, thresholdNum)
	for i, s := range mapOfSignersParam {
		inputMap := make(map[uint32]*participant.Round3Bcast, thresholdNum-1)
		for j := range mapOfSignersParam {
			if i == j {
				continue
			}
			inputMap[j] = round3BroadcastMap[j]
		}
		round4BroadcastMap[i], err = s.SignRound4(inputMap)
		if err != nil {
			return false
		}
	}

	// Фаза 5
	round5BroadcastMap := make(map[uint32]*participant.Round5Bcast, thresholdNum)
	peer2peerCommunicationMapRound5 := make(map[uint32]map[uint32]*participant.Round5P2PSend, thresholdNum)
	for i, s := range mapOfSignersParam {
		inputMap := make(map[uint32]*participant.Round4Bcast, thresholdNum-1)
		for j := range mapOfSignersParam {
			if i == j {
				continue
			}
			inputMap[j] = round4BroadcastMap[j]
		}
		round5BroadcastMap[i], peer2peerCommunicationMapRound5[i], err = s.SignRound5(inputMap)
		if err != nil {
			return false
		}
	}

	// Фаза 6
	round6BroadcastMap := make(map[uint32]*participant.Round6FullBcast, thresholdNum)
	for i, s := range mapOfSignersParam {
		inputMap := make(map[uint32]*participant.Round5Bcast, thresholdNum-1)
		for j := range mapOfSignersParam {
			if i == j {
				continue
			}
			inputMap[j] = round5BroadcastMap[j]
		}
		round6BroadcastMap[i], err = s.SignRound6Full(messageHash[:], inputMap, peer2peerCommunicationMapRound5[i])
		if err != nil {
			return false
		}
	}

	// Фінальна фаза створення підпису
	var signatureFinal *curves.EcdsaSignature
	for i, s := range mapOfSignersParam {
		inputMap := make(map[uint32]*participant.Round6FullBcast, thresholdNum-1)
		for j := range mapOfSignersParam {
			if i == j {
				continue
			}
			inputMap[j] = round6BroadcastMap[j]
		}

		signatureFinal, _ = s.SignOutput(inputMap)

	}

	fmt.Printf("\nЦифровий підпис: (%d %d)\n", signatureFinal.R, signatureFinal.S)

	sigR = signatureFinal.R
	sigS = signatureFinal.S

	publicKey := ecdsa.PublicKey{
		Curve: ecc.P256k1(), //secp256k1
		X:     privatKey.X,
		Y:     privatKey.Y,
	}

	rtn := ecdsa.Verify(&publicKey, messageHash[:], signatureFinal.R, signatureFinal.S)
	fmt.Printf("\nПідпис вірний: %v", rtn)

	duration := time.Since(start)

	timeStr = duration.String()
	fmt.Println("\nВитрачений час: " + timeStr)
	return rtn
}

func main() {
	a := app.New()
	win := a.NewWindow("Підпис")

	win.Resize(fyne.NewSize(800, 500))

	first := widget.NewLabel("")
	second := widget.NewLabel("")
	third := widget.NewLabel("")
	fourth := widget.NewLabel("")
	fifth := widget.NewLabel("")
	sixth := widget.NewLabel("")
	final := widget.NewLabel("")

	sign := widget.NewLabel("Запустити підпис")

	btn := widget.NewButton("Створити підпис", func() {
		a := start()
		sign.Text = "Підпис створено"
		first.Text = "Повідомлення:  " + signText
		second.Text = "Випадковий секрет:  " + secret.Text(16)
		third.Text = "Публічний ключ:  " + pkX.Text(16) + "\n" + pkY.Text(16)
		fourth.Text = "Частки секрету: 1-ша:" + hex.EncodeToString(share1) + "\n" + " 2-га: " + hex.EncodeToString(share2)
		fifth.Text = "Цифровий підпис:  " + pkX.Text(16) + "\n" + pkY.Text(16)
		sixth.Text = "Підпис вірний?: " + strconv.FormatBool(a)
		final.Text = "Витрачений час:  " + timeStr
		sign.Refresh()
		first.Refresh()
		second.Refresh()
		third.Refresh()
		fourth.Refresh()
		fifth.Refresh()
		sixth.Refresh()
		final.Refresh()

	})

	win.SetContent(container.NewVBox(
		sign,
		btn,
		first,
		second,
		third,
		fourth,
		fifth,
		sixth,
		final,
	))

	win.ShowAndRun()
}

/*

PATH='/Users/admin/micromamba/bin:/Users/admin/micromamba/condabin:/opt/local/bin:/opt/local/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/Applications/VMware Fusion.app/Contents/Public:/usr/local/go/bin:/usr/local/share/dotnet:~/.dotnet/tools'

*/
