iRODS Sudo Microservices
========================

The Sudo microservices empower users to execute operations typically
reserved for iRODS administrators. Combined with application of the
iRODS programmable policies they facilitate fine-grained delegation of
authority.  The supported operations cover managing users and groups,
metadata and ACLs.

See [Documentation for individual microservices](#documentation-for-individual-microservices)
for the list of microservices and their parameter specification.

## Download ##

We distribute DEB and RPM packages for iRODS 4.3.3 and iRODS 4.2.12:

- [`irods-sudo-microservices-4.3.3_1.0.0`](https://github.com/UtrechtUniversity/irods-sudo-microservices/releases/tag/4.3.3_1.0.0)
- [`irods-sudo-microservices-4.2.2_1.0.0`](https://github.com/UtrechtUniversity/irods-sudo-microservices/releases/tag/4.2.12_1.0.0)

The left side (4.3.3) of the version number indicates the compatible
iRODS server version. The right side (1.2.0) is the major/minor/patch
version of the microservices themselves.

## Installation ##

Sudo microservices can be installed using the packages provided on the
[releases page](https://github.com/UtrechtUniversity/irods-sudo-microservices/releases/).

You can also build the microservices yourself, see
[Building from source](#building-from-source).

## Security Considerations ##

Sudo Microservices provide a way for normal iRODS users to perform
normally restricted operations. The administrator-defined policy rules
are the only barrier that can perform authorization and check the
validity of each msi call. Misconfiguration can result in security
breaches.

With that in mind, we have a few recommendations for policy
implementors:

- Keep policy rules concise and readable
- Document each condition extensively
- Use a whitelist approach instead of a blacklist approach

## Configuration / Policy implementation ##

By default, when no policies have been defined, access to the sudo
microservices is denied to all users.
By implementing pre- and postproc policy rules, you can selectively
grant access.

An example policy ruleset is provided in `policies.re`, which is
installed in `/etc/irods/sudo-default-policies.re`. This file can be
added to the ruleset list in the iRODS server config json.
You can use this file as a template for your policy
implementations.

Every microservice has its own pre- and postproc policy rule. The naming
scheme follows this example:

    msiSudoUserAdd() has policy rules acPreSudoUserAdd() and acPostSudoUserAdd()

The pre and post rule receive the same set of parameters that are
passed to the microservice itself. Additionally, they can make
decisions based on session variables like `$userNameClient` and
`$rodsZoneClient`.

As an example, the following preproc rule for msiSudoGroupAdd
restricts the operation to a single user with a specific name:

```
acPreSudoGroupAdd(*groupName, *initialAttr, *initialValue, *initialUnit, *policyKv) {
    if ("$userNameClient#$rodsZoneClient" == "piet#tempZone") {
        succeed;
    } else {
        fail;
    }
}
```

### Logging ###

You can log msi execution similar to how you can log other iRODS
operations that use policy enforcement points:
Create a pre- rule for each microservice, and make it log and fail:

```
acPreSudoGroupAdd(*groupName, *initialAttr, *initialValue, *initialUnit, *policyKv) {
    writeLine("serverLog", "In acPreSudoGroupAdd, group is <*groupName>, actor is <$userNameClient#$rodsZoneClient>");
    fail;
}
```

Make sure this pre- rule is executed before any other implementations
of the same policy, for example by adding it to a ruleset that is
loaded before the ruleset in which authorization takes place.

If you do not want to have multiple implementations of the pre rule,
simply insert the logging calls into the authorizing rule.

## Calling Sudo Microservices ##

A microservice call will succeed (return status 0) only if its 'pre-'
rule, the operation itself *and* the post rule succeed.
If any of these three parts fail the microservice is failed
immediately and an error code is returned.

## Documentation for individual microservices ##

Every microservice has a `*policyKv` as the last parameter. This
parameter can be used to pass extra information to the policy pre- and
post- rules. The microservices themselves do not use this parameter.

If you do not make use of this feature, you can pass an empty kv list
or an empty string `""` in its place.

### User and group management ###

####  `msiSudoUserAdd(*userName, *initialAttr, *initialValue, *initialUnit, *policyKv)` ####

Creates a new iRODS user of type `rodsuser`. The `*initialAttr`,
`*initialValue` and optionally `*initialUnit` are applied as metadata
to the user if they are not empty.

#### `msiSudoUserRemove(*userName, *policyKv)` ####

Removes the given iRODS user.

#### `msiSudoGroupAdd(*groupName, *initialAttr, *initialValue, *initialUnit, *policyKv)` ####

Creates a new iRODS group of type `rodsgroup`. The `*initialAttr`,
`*initialValue` and optionally `*initialUnit` are applied as metadata
to the user if they are not empty.

#### `msiSudoGroupRemove(*groupName, *policyKv)` ####

Removes the given iRODS group.

#### `msiSudoGroupMemberAdd(*groupName, *userName, *policyKv)` ####

Adds a user to a group.

#### `msiSudoGroupMemberRemove(*groupName, *userName, *policyKv)` ####

Removes a user from a group.

### ACL operations ###

#### `msiSudoObjAclSet(*recursive, *accessLevel, *otherName, *objPath, *policyKv)` ####

Modifies ACLs on data objects and collections.

`*recursive` can be either the string `"recursive"` to apply the change
recursively, or an empty string `""` to modify only the given object.

`*accessLevel` can be one of `null`, `read`, `write`, `own`, `inherit`
or `noinherit` similar to the parameters for `ichmod`.

When `*accessLevel` is not `inherit` or `noinherit`, the `*otherName`
must be filled with the user or group name whose access to the given
object will be changed.

### Metadata operations ###

In all metadata operations `*objType` indicates the type of object. Its possible values are the same as for `imeta`:

- `-d` = data object
- `-C` = collection
- `-u` = user or group
- `-R` = resource

#### `msiSudoObjMetaSet(*objName, *objType, *attribute, *value, *unit, *policyKv)` ####

Similar to `imeta set`:
Set an AVU on an object.

If the given `*attribute` already exists, it is overwritten with the
new `*value` and `*unit`.

#### `msiSudoObjMetaAdd(*objName, *objType, *attribute, *value, *unit, *policyKv)` ####

Similar to `imeta add`:
Add an AVU to an object. The given AVU combination must not already
exist for the given object.

#### `msiSudoObjMetaRemove(*objName, *objType, *wildcards, *attribute, *value, *unit, *policyKv)` ####

Similar to `imeta rm(w)`:
Remove metadata from an object.

`*wildcards` indicates whether `%` characters in AVU parameters should
be interpreted as wildcards. The value of this parameter can be either
the string `"wildcards"` or an empty string `""`.

## Building from source ##

To build from source, the following build-time dependencies must be
installed:

- `cmake`
- `make`
- `irods-devel`
- `irods-externals-cmake3.21.4-0`
- `irods-externals-clang13.0.0-0`
- `irods-externals-json3.10.4-0`
- `irods-externals-fmt8.1.1-0`
- `rpmdevtools` (if you are creating an RPM)

Follow these instructions to build from source:

- First, browse to the directory where you have unpacked the source
  distribution.

- Check whether your umask is set to a sane value. If the output of
  `umask` is not `0022`, run `umask 0022` to fix it. This is important
  for avoiding conflicts in created packages later on.

- Create and generate a build directory:

```bash
mkdir build
cd build
/opt/irods-externals/cmake3.21.4-0/bin/cmake ..
```

- Compile the project

```bash
make
```

Now you can either build an RPM or install the project without a package
manager.

**To create a package:**

```bash
make package
```

That's it, you should now have an RPM in your build directory which you
can install using yum.

**To install without creating a package**

```bash
make install
```

This will install the `.so` files into the microservice plugin
directory.

## Bugs and ToDos ##

Please report any issues you encounter on the
[issues page](https://github.com/UtrechtUniversity/irods-sudo-microservices/issues/).

## Authors ##

- [Chris Smeele](https://github.com/cjsmeele)

## Contact information ##

For questions or support, contact Chris Smeele or Ton Smeele either
directly or via the
[Utrecht University RDM](http://www.uu.nl/en/research/research-data-management/contact-us)
page.

## License ##

Copyright (c) 2016-2024 Utrecht University.

Sudo Microservices is licensed under the GNU Lesser General Public
License version 3 or higher (LGPLv3+). See the COPYING.LESSER file for
details.
