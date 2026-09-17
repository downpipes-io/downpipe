package custody

import (
	"bytes"
	"fmt"
)

// Inputs is one recombine invocation after file loading: labelled share files, raw
// (emailed) share bodies, or the whole wrapping key, plus the parsed envelope and an
// optional threshold hint for a set with no labelled file to carry it.
type Inputs struct {
	Labelled      []*ShareFile
	Raw           [][]byte
	WrappingKey   []byte
	Envelope      *EnvelopeFile
	ThresholdHint int
}

// Recombine recovers the identity-file plaintext from the custody artefacts. Order:
// assemble the distinct share set (labelled files must agree on n, threshold and
// checksum; an identical duplicate is dropped with a notice; a same-index different-body
// pair is refused), gate on the threshold when one is known, recombine, verify the
// public checksum when one is known (the early clear signal), then the authoritative
// authenticated decrypt. The wrapping key is wiped before returning; the caller owns
// wiping the returned plaintext once written.
func Recombine(in Inputs) (plaintext []byte, notices []string, err error) {
	if in.Envelope == nil {
		return nil, nil, &ArtefactError{Msg: "an envelope file is required"}
	}
	var key []byte
	switch {
	case in.WrappingKey != nil:
		if len(in.Labelled)+len(in.Raw) > 0 {
			return nil, nil, &ArtefactError{Msg: "supply shares or a wrapping key, not both"}
		}
		key = append([]byte(nil), in.WrappingKey...)
	default:
		shares, ns, serr := assembleShares(in)
		notices = ns
		if serr != nil {
			return nil, notices, serr
		}
		key, serr = Combine(shares)
		if serr != nil {
			return nil, notices, serr
		}
		if checksum := labelledChecksum(in.Labelled); checksum != nil && !VerifyChecksum(key, checksum) {
			Wipe(key)
			return nil, notices, &IntegrityError{Msg: "the recombined key fails the public checksum: one of your shares is incorrect, or the shares are from different ceremonies; retry with exactly the threshold count of known-good shares"}
		}
	}
	defer Wipe(key)
	pt, oerr := OpenEnvelope(in.Envelope, key)
	if oerr != nil {
		return nil, notices, oerr
	}
	return pt, notices, nil
}

// assembleShares merges the labelled and raw shares into one distinct set, enforcing
// the labelled files' cross-file consistency and the threshold gate when a threshold is
// known (from any labelled file, else the hint).
func assembleShares(in Inputs) ([][]byte, []string, error) {
	var notices []string
	threshold := in.ThresholdHint
	var checksum []byte
	var n int
	for i, sf := range in.Labelled {
		if i == 0 {
			threshold, n, checksum = sf.Threshold, sf.N, sf.Checksum
			continue
		}
		if sf.Threshold != threshold || sf.N != n {
			return nil, nil, &ArtefactError{Msg: fmt.Sprintf("share file %d declares %d-of-%d but an earlier file declares %d-of-%d; the files are from different ceremonies", i+1, sf.Threshold, sf.N, threshold, n)}
		}
		if !bytes.Equal(sf.Checksum, checksum) {
			return nil, nil, &ArtefactError{Msg: fmt.Sprintf("share file %d carries a different wrapping-key checksum from an earlier file; the files are from different ceremonies", i+1)}
		}
	}
	byIndex := map[byte][]byte{}
	var shares [][]byte
	add := func(share []byte, origin string) error {
		prev, ok := byIndex[share[0]]
		if ok {
			if bytes.Equal(prev, share) {
				notices = append(notices, fmt.Sprintf("dropped a duplicate of share %d (%s); the same custodian was supplied twice", share[0], origin))
				return nil
			}
			return &ArtefactError{Msg: fmt.Sprintf("two shares carry index %d with different bodies; one is corrupt or from another ceremony", share[0])}
		}
		byIndex[share[0]] = share
		shares = append(shares, share)
		return nil
	}
	for _, sf := range in.Labelled {
		if err := add(sf.Share, "a labelled file"); err != nil {
			return nil, notices, err
		}
	}
	for _, r := range in.Raw {
		if err := add(r, "a raw share"); err != nil {
			return nil, notices, err
		}
	}
	if len(shares) == 0 {
		return nil, notices, &ArtefactError{Msg: "no shares supplied"}
	}
	if threshold > 0 && len(shares) < threshold {
		return nil, notices, &ArtefactError{Msg: fmt.Sprintf("need %d distinct shares to recombine, got %d", threshold, len(shares))}
	}
	return shares, notices, nil
}

// labelledChecksum returns the set's public checksum when any labelled file carried
// one; an all-raw (emailed) set has none, and the authenticated decrypt alone decides.
func labelledChecksum(labelled []*ShareFile) []byte {
	if len(labelled) == 0 {
		return nil
	}
	return labelled[0].Checksum
}
