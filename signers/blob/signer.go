package blob

import (

    "io"
    "os"
    "errors"
    "crypto"
    "crypto/rand"

    "github.com/rs/zerolog"
    "github.com/sassoftware/relic/v8/lib/audit"
    "github.com/sassoftware/relic/v8/lib/certloader"
    "github.com/sassoftware/relic/v8/signers"

)


var BlobSigner = &signers.Signer{
	Name:      "blob",
	//Magic:     magic.FileTypeUnknown
	//CertTypes: signers.CertTypeX509,
	CertTypes: signers.CertTypePgp,
	//Transform: transform,
	Sign:      sign,
	Verify:    verify,
}

func init() {
    signers.Register(BlobSigner)
}

func formatLog(attrs *audit.Info) *zerolog.Event {
    return attrs.AttrsForLog("blob.")
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
    privKey := cert.PrivateKey.(crypto.Signer)
    hash := opts.Hash.New()
    if _, err := io.Copy(hash, r); err != nil {
        return nil, err
    }
    digest := hash.Sum(nil)
    return privKey.Sign(rand.Reader, digest, opts.Hash)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
    return nil, errors.New("Not implemented")
}
