package main

import (
	"go/ast"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Every command that takes a break-glass key must take it through the shared identity source.
//
// WHY A GATE AND NOT A COMMENT. identity_source.go already states this rule: commands register the shared
// flags "so a new command cannot accidentally support only half of the sources and leave split-custody
// operators back on the disk path". The rule was written down and then broken. unseal-export declared its
// own --identity string flag and parsed the key itself, so it was the one command a split-custody holder
// could not run, and it is the command that exists for total account loss. A comment describing a
// preference is not a check. This is the check.
//
// It asserts a PROPERTY rather than an import: no command file outside the two named below may register a
// flag called "identity" or parse a KEM private key of its own. Either of those means a second, narrower
// way into the same decision, which is exactly how the last one drifted.
//
// THE EXEMPTIONS, and both are exemptions for a reason rather than for convenience:
//   - identity_source.go IS the shared source.
//   - recombine.go is the command whose whole job is to turn shares into an identity.key, so it declares the
//     custody artefacts directly and parses the recovered key to check it before writing it out.
//
// IT READS THE PARSED SOURCE, NOT THE TEXT. The first version matched three regular expressions over the
// file's bytes, and a single realistic edit defeated BOTH halves at once. Dropping restore.go's
// `idf := addIdentityFlags(fs, ...)` for a command-local registrar, and leaving the old call behind as a
// comment, was accepted: the positive half saw `addIdentityFlags(` in the comment and called it satisfied,
// and the negative half missed the new registration because the flag target was written `new(string)`
// rather than `&something`, which the pattern required. Naming the flag set `f` instead of `fs` or `flags`
// defeated it a second, independent way. Restore, the flagship recovery command, could have stopped
// offering the split-custody route entirely with the gate still green.
//
// The parser closes all of those by construction: a comment is not in the tree, a registration is a call
// whatever the receiver is named and whatever shape its target takes, and an aliased import of the crypto
// package still resolves to the same package. Accounting is TOTAL: every flag registration must yield a
// name this test can read, and one that does not fails the test naming the position, rather than falling
// out of a no-match branch and being counted as absent.

// Pinned rather than derived. A new command that decrypts has to be added here consciously, which is the
// moment to ask whether it registered the shared flags. Deriving the list from the files would make the
// gate agree with whatever the code does, which is the one thing a gate must not do.
// keys.go is on the list for its --fingerprint mode, which names the key an operator holds by
// deriving its public fingerprint. It resolves an identity like the rest, so it takes the shared
// source and a split-custody holder can fingerprint the key their shares rebuild without writing a
// complete key to disk.
var commandsResolvingAnIdentity = []string{"inspect.go", "keys.go", "prune.go", "restore.go", "unseal_export.go", "verify.go"}

var identityFlagExemptions = map[string]bool{"identity_source.go": true, "recombine.go": true}

const cryptoPkgPath = "github.com/downpipes-io/downpipe/internal/crypto"

// The flag package's registrars, and which argument carries the flag NAME. The Var forms take the target
// first, the rest take the name first. Func and BoolFunc take the name first as well.
var flagRegistrars = map[string]int{
	"Bool": 0, "BoolVar": 1,
	"Duration": 0, "DurationVar": 1,
	"Float64": 0, "Float64Var": 1,
	"Func": 0, "BoolFunc": 0,
	"Int": 0, "IntVar": 1,
	"Int64": 0, "Int64Var": 1,
	"String": 0, "StringVar": 1,
	"TextVar": 1,
	"Uint":    0, "UintVar": 1,
	"Uint64": 0, "Uint64Var": 1,
	"Var": 1,
}

// cryptoAlias returns the local name the file uses for the crypto package, so an aliased import cannot
// take a private-key parse out of this gate's sight. It returns "" when the file does not import crypto.
func cryptoAlias(file *ast.File) string {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != cryptoPkgPath {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return "crypto"
	}
	return ""
}

// registeredFlagNames returns every flag name the file registers. A registration whose name argument is
// not a readable string constant is reported to the caller by position, so it fails the test rather than
// being skipped: a name this gate cannot read is a name that could be "identity".
func registeredFlagNames(fset *token.FileSet, file *ast.File) (names []string, unreadable []string) {
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		idx, ok := flagRegistrars[sel.Sel.Name]
		if !ok || len(call.Args) <= idx {
			return true
		}
		// A method with one of these names on something that is not a flag set would be counted here too.
		// That direction is safe: it can only make the gate stricter, never blinder, and this package has
		// no such method.
		name, ok := stringConst(call.Args[idx])
		if !ok {
			unreadable = append(unreadable, fset.Position(call.Args[idx].Pos()).String()+" ("+sel.Sel.Name+")")
			return true
		}
		names = append(names, name)
		return true
	})
	return names, unreadable
}

// callsFunction reports whether the file contains a call to a plain function of the given name. It is an
// AST search, so a call left behind in a comment does not count.
func callsFunction(file *ast.File, name string) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

// callsPackageFunction reports whether the file calls pkg.name, under the file's own spelling of pkg.
func callsPackageFunction(file *ast.File, alias, name string) bool {
	if alias == "" {
		return false
	}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != name {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == alias {
			found = true
			return false
		}
		return true
	})
	return found
}

// buildsAnIdentitySourceItself reports whether the file constructs an identityFlags of its own, at the
// position it does so.
//
// THE THIRD ROUTE. The gate asserted two properties, a flag named "identity" and a KEM parse of one's
// own, and a command could take a break-glass key by neither. Proven: attest.go registering
// --break-glass-key and calling (&identityFlags{path: *keyPath}).resolve() passed the whole package,
// while accepting a key FILE only. A split-custody holder would have had to run recombine first and
// write the complete break-glass key to disk, which is the arrangement split custody exists to avoid,
// and it is the outcome this gate names in its own failure message.
//
// Constructing the shared struct outside the shared source is a second, narrower way into the same
// decision whatever the flag is called, so the construction itself is what is checked.
func buildsAnIdentitySourceItself(fset *token.FileSet, file *ast.File) string {
	where := ""
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		ident, ok := lit.Type.(*ast.Ident)
		if !ok || ident.Name != "identityFlags" {
			return true
		}
		where = fset.Position(lit.Pos()).String()
		return false
	})
	return where
}

func TestOnlyTheSharedSourceRegistersAnIdentityFlag(t *testing.T) {
	fset, files := commandFiles(t)

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var offenders []string
	for _, name := range names {
		if identityFlagExemptions[name] {
			continue
		}
		file := files[name]
		flags, unreadable := registeredFlagNames(fset, file)
		if len(unreadable) > 0 {
			t.Fatalf("%s registers a flag whose name this gate cannot read, so it cannot be shown not to be --identity: %s\n"+
				"Write the flag name as a string literal, or teach this test the new form.", name, strings.Join(unreadable, ", "))
		}
		for _, f := range flags {
			if f == "identity" {
				offenders = append(offenders, name+" registers its own --identity flag")
				break
			}
		}
		if callsPackageFunction(file, cryptoAlias(file), "ParseKEMPrivate") {
			offenders = append(offenders, name+" parses a KEM private key of its own")
		}
		if where := buildsAnIdentitySourceItself(fset, file); where != "" {
			offenders = append(offenders, name+" builds an identityFlags of its own at "+where)
		}
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("a command takes a break-glass key without going through addIdentityFlags:\n  %s\n\n"+
			"Use addIdentityFlags(fs, help) and idf.resolve(). A command with its own --identity accepts a key\n"+
			"FILE only, so a split-custody holder has to run recombine first, which writes the complete\n"+
			"break-glass key to disk. That is the arrangement split custody exists to avoid.",
			strings.Join(offenders, "\n  "))
	}
}

// The positive half. The check above would also pass if every command stopped accepting a key at all, so
// the pinned set has to be present and each member has to actually CALL the shared registrar. The call is
// read off the tree, because the whole hole this test had was accepting a call that was only a comment.
func TestEveryDecryptingCommandUsesTheSharedSource(t *testing.T) {
	_, files := commandFiles(t)
	for _, name := range commandsResolvingAnIdentity {
		file, ok := files[name]
		if !ok {
			t.Errorf("%s is pinned as a command that resolves an identity but is not in this package", name)
			continue
		}
		if !callsFunction(file, "addIdentityFlags") {
			t.Errorf("%s no longer calls addIdentityFlags, so it has stopped offering the split-custody route", name)
		}
	}
}

// The set has to match in BOTH directions. A new command that calls the shared registrar and is not on the
// pinned list is the drift the pin exists to make someone notice: it is a new way into the break-glass key,
// and adding the row here is the moment to ask whether it also needs a docs entry. This is set equality
// against a hand-kept list, not derivation from the code, so neither side can quietly win.
func TestThePinnedDecryptingSetMatchesTheCommandsThatRegisterIt(t *testing.T) {
	_, files := commandFiles(t)

	pinned := map[string]bool{}
	for _, name := range commandsResolvingAnIdentity {
		pinned[name] = true
	}

	var unpinned []string
	for name, file := range files {
		if pinned[name] || identityFlagExemptions[name] {
			continue
		}
		if callsFunction(file, "addIdentityFlags") {
			unpinned = append(unpinned, name)
		}
	}
	if len(unpinned) > 0 {
		sort.Strings(unpinned)
		t.Fatalf("these commands take a break-glass identity but are not in commandsResolvingAnIdentity: %s\n"+
			"Add them to the pin. The pin is what makes a command losing the shared registrar fail, so a\n"+
			"command outside it can drop split custody without anything noticing.", strings.Join(unpinned, ", "))
	}
}
