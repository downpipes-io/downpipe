# Recovering this archive

You need the destination bucket, and from your recovery kit two files: your offline break-glass identity, and signer.pub, the operator signer public key this archive's signatures are verified against. Both restore and verify require --signer, so a kit holding only the identity cannot recover. The recovery involves neither Cloudflare nor the vendor.

    downpipe restore --archive <dir> --run <runId> --identity identity.key \
      --signer signer.pub --out <dir> --apply

Without --apply that command plans the restore and writes nothing, which is the safe way to look at an archive before you commit to it. With --apply the recovered records are written under --out.

If your break-glass key is held as an M-of-N custody quorum rather than as a single file, give the shares to the same command instead of --identity. Pass one --share for each custodian your quorum requires, from any M of the N; they are combined in memory for that one command and wiped, so no complete key is written to disk:

    downpipe restore --archive <dir> --run <runId> --signer signer.pub --out <dir> --apply \
      --share share-1.txt --share share-2.txt --share share-3.txt --envelope wrapped-identity.txt

The break-glass private key is the only universal way to recover, and signer.pub has to be supplied with it. The format is specified in FORMAT.md and pinned by the conformance vectors it references.
