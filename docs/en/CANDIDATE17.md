Historical candidate note; see README and release notes for current status.

# Candidate 17 – concurrent Field message synchronization

Application 2.5.0~preview20261024.17sync1. Unchanged driver 2.7.9~gutochat20261024.4.
Internal candidate; not published or installed yet.

Field now acquires a SQLite write reservation before checking the message-sync
page's starting cursor. Two concurrent pages can no longer both accept the
same stale cursor and subsequently move it backwards. Only one statement is
added in Field/message_store.py; all other AST remains identical to candidate16.
Base runtime code and the driver remain unchanged.

Five isolated storage tests cover duplicates/conflicts, orphan replay markers,
storage-fault rollback, page/cursor rollback and competing synchronization
writers. Four pass before the fix and the concurrency test fails; all five pass
after it on Windows and Pi/Python 3.13.5/SQLite3.46.1. These synthetic tests do not
establish full operational load, replay or recovery acceptance.

Candidate16 remains the installed physically accepted baseline: both GUIs open,
Base displays recipient acknowledgement and receives the T433 reply via X433.
The earlier Base startup fix, ACK fix, matching source/build kit, notices and
all 35 roadmap tracks are retained. No new reboot test performed. Remaining code
review, periodic SQLite contention, full replay/restore and final publication
remain open. Production machines, GitHub and website are unchanged.
