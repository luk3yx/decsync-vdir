# decsync-vdir

Synchronises [DecSync](https://github.com/39aldo39/DecSync) contacts/calendars
with a [vdir](https://vdirsyncer.pimutils.org/en/stable/vdir.html).

## Usage

Make sure you have Go 1.16 or later installed.

Building decsync-vdir:

```
$ go build decsync-vdir.go
```

Syncing a contacts directory with DecSync:

```
$ ./decsync-vdir /path/to/decsync/contacts/<uuid> /path/to/vdir .vcf
```

Syncing a calendar directory with DecSync:

```
$ ./decsync-vdir /path/to/decsync/calendars/<uuid> /path/to/vdir .ics
```

The vdir directory will be created if it doesn't already exist.

## Limitations

 - Deleting a file in the vdir will not delete it on DecSync, `decsync-vdir`
   will recreate the file inside the vdir instead.
 - `decsync-vdir` doesn't store entries created on other devices in its own
   storage directory under `v2`.
