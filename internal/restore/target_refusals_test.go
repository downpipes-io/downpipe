package restore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The remaining refusals in the three restore targets, and in the two entry points' first
// step. Each is something an operator can hit on their first attempt, in the middle of the
// disaster that made them run this binary, and each was uncovered: the message was the only
// thing standing between them and a wrong diagnosis, and nothing checked the message.
//
// Every assertion is on the specific refusal. An error-only assertion would pass when the
// reader refused for the wrong reason, and here the wrong reason costs an operator the time
// they have least of.

// wantTargetRefusal asserts what the operator is told, not merely that they were told
// something.
func wantTargetRefusal(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no refusal at all, want one saying %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("the refusal reads %q, want it to say %q", err, want)
	}
}

// TestDirTargetRefusesAnOutputPathThatIsNotADirectory covers the two ways enumerating the
// output directory fails. Both are ordinary mistakes with a shell: giving the path of a file
// that already exists, and giving a path whose parent is a file rather than a directory. A
// missing directory is deliberately NOT an error (a first restore into a fresh path plans
// cleanly), so these two are what is left, and telling them apart is the whole value: one
// means "you named a file", the other means "the path you named cannot exist".
func TestDirTargetRefusesAnOutputPathThatIsNotADirectory(t *testing.T) {
	base := t.TempDir()
	notADir := filepath.Join(base, "restore.tar")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("the output path is a file", func(t *testing.T) {
		existing, err := NewDirTarget(notADir).Existing()
		wantTargetRefusal(t, err, "output path "+notADir+" is not a directory")
		if existing != nil {
			t.Fatalf("a refused enumeration must return no key set, got %v", existing)
		}
	})

	t.Run("the output path sits under a file", func(t *testing.T) {
		under := filepath.Join(notADir, "records")
		existing, err := NewDirTarget(under).Existing()
		wantTargetRefusal(t, err, "inspect output directory")
		if existing != nil {
			t.Fatalf("a refused enumeration must return no key set, got %v", existing)
		}
	})

	t.Run("a missing directory is an empty set, not a refusal", func(t *testing.T) {
		existing, err := NewDirTarget(filepath.Join(base, "not-yet")).Existing()
		if err != nil {
			t.Fatalf("a first restore into a fresh path must plan cleanly, got %v", err)
		}
		if len(existing) != 0 {
			t.Fatalf("a missing directory must enumerate to nothing, got %v", existing)
		}
	})
}

// TestDirTargetWriteStreamRefusesAKeyItCannotMakeADirectoryFor covers the streamed write's
// own MkdirAll failure. Write's equivalent was already exercised; WriteStream's was not, and
// WriteStream is the path a value larger than memory takes, which is precisely the record an
// operator cannot work around by hand if the message sends them the wrong way.
func TestDirTargetWriteStreamRefusesAKeyItCannotMakeADirectoryFor(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "blocked"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := NewDirTarget(base).WriteStream("blocked/value", strings.NewReader("payload"), 7)
	wantTargetRefusal(t, err, "create directory for blocked/value")
}

// failingEnvWriter is a dotenv sink that cannot be written to, standing in for a closed pipe
// or a full disk under the operator's shell redirection.
type failingEnvWriter struct{ err error }

func (f failingEnvWriter) Write([]byte) (int, error) { return 0, f.err }

// TestEnvTargetRefusesToRedefineAndReportsAFailedWrite covers the env target's two remaining
// refusals.
//
// The redefinition refusal is the load-bearing one. An env target writes dotenv lines that an
// operator sources, so silently emitting a second assignment for a name would let a restored
// record overwrite a variable the environment already set, or let two records in one run
// overwrite each other, with the last line quietly winning. Both directions are covered: a
// name already present before the run, and a name this run has itself already written.
func TestEnvTargetRefusesToRedefineAndReportsAFailedWrite(t *testing.T) {
	t.Run("a name the environment already set", func(t *testing.T) {
		var sink strings.Builder
		target := NewEnvTarget(&sink, []string{"DATABASE_URL"})
		err := target.Write("DATABASE_URL", []byte("postgres://restored"))
		wantTargetRefusal(t, err, "environment variable DATABASE_URL is already set; refusing to redefine it")
		if sink.String() != "" {
			t.Fatalf("a refused write must emit no dotenv line, got %q", sink.String())
		}
	})

	t.Run("a name this run already wrote", func(t *testing.T) {
		var sink strings.Builder
		target := NewEnvTarget(&sink, nil)
		if err := target.Write("API_TOKEN", []byte("first")); err != nil {
			t.Fatalf("the first write must succeed: %v", err)
		}
		err := target.Write("API_TOKEN", []byte("second"))
		wantTargetRefusal(t, err, "environment variable API_TOKEN is already set; refusing to redefine it")
		if got := sink.String(); got != "API_TOKEN='first'\n" {
			t.Fatalf("the second write must not reach the sink, got %q", got)
		}
	})

	t.Run("the sink cannot be written to", func(t *testing.T) {
		target := NewEnvTarget(failingEnvWriter{err: fmt.Errorf("broken pipe")}, nil)
		err := target.Write("API_TOKEN", []byte("v"))
		wantTargetRefusal(t, err, "write env line for API_TOKEN")
		// The cause has to survive, or the operator is told the name and not the reason.
		wantTargetRefusal(t, err, "broken pipe")
	})
}

// TestDiscardTargetKeyIsMemoisedPerName covers the memoisation hit in DiscardTarget.Key. The
// contract it holds is not cosmetic: Key is called once by the planner and again at apply time
// for the same name, so a Key that returned a fresh ordinal on the second call would make the
// apply write to a key the plan never claimed, and the discard target exists to verify every
// record, which means every record must be planned as a write.
func TestDiscardTargetKeyIsMemoisedPerName(t *testing.T) {
	target := NewDiscardTarget()
	first, err := target.Key("records/alpha")
	if err != nil {
		t.Fatalf("the discard target never refuses a name: %v", err)
	}
	again, err := target.Key("records/alpha")
	if err != nil {
		t.Fatalf("the discard target never refuses a name: %v", err)
	}
	if first != again {
		t.Fatalf("the same name produced two keys, %q then %q: the apply would write to a key the plan never claimed", first, again)
	}
	other, err := target.Key("records/beta")
	if err != nil {
		t.Fatalf("the discard target never refuses a name: %v", err)
	}
	if other == first {
		t.Fatalf("two names collided on the key %q, so one record would not be planned as a write and would never be verified", other)
	}
}

// unenumerableTarget is a target whose existing state cannot be read, which is what a
// destination the operator can write to but not list looks like from here.
type unenumerableTarget struct{}

func (unenumerableTarget) Kind() string                    { return "fake" }
func (unenumerableTarget) Key(name string) (string, error) { return name, nil }
func (unenumerableTarget) Existing() (map[string]struct{}, error) {
	return nil, fmt.Errorf("status 403")
}
func (unenumerableTarget) Write(string, []byte) error { return nil }
func (unenumerableTarget) Close() error               { return nil }

// TestBothEntryPointsRefuseWhenTheTargetCannotBeEnumerated covers the first step of Apply and
// of ApplyStreaming. Enumerating the target is what the no-clobber plan is built from, so a
// failure here has to stop the restore rather than proceed with an empty set: an empty set
// reads as "the destination is empty", and the whole plan would then classify every record as
// a clean write over whatever is actually there.
func TestBothEntryPointsRefuseWhenTheTargetCannotBeEnumerated(t *testing.T) {
	source := rdr([2]string{"AAA", "v1"})

	t.Run("Apply", func(t *testing.T) {
		plan, res, err := Apply(source, unenumerableTarget{}, true)
		wantTargetRefusal(t, err, "enumerate target state")
		wantTargetRefusal(t, err, "status 403")
		if plan != nil || res != nil {
			t.Fatalf("a refused apply must return neither plan nor result, got plan=%v res=%v", plan, res)
		}
	})

	t.Run("ApplyStreaming", func(t *testing.T) {
		plan, res, err := ApplyStreaming(source, unenumerableTarget{}, true)
		wantTargetRefusal(t, err, "enumerate target state")
		wantTargetRefusal(t, err, "status 403")
		if plan != nil || res != nil {
			t.Fatalf("a refused apply must return neither plan nor result, got plan=%v res=%v", plan, res)
		}
	})
}
