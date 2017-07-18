test {
    #*a = errorcode(msiSudoUserAdd("pietje", "", "", "", ""));
    #*a = errorcode(msiSudoUserAdd(1, "", "", "", ""));
    #writeLine("stdout", "result: *a");
    #succeed;
    #writeLine("stdout", "Set");
    #msiSudoObjAclSet("recursive", "read", "chris", "/tempZone/home/pietje", "");
    #writeLine("stdout", "Unset");
    #msiSudoObjAclSet("recursive", "null", "chris", "/tempZone/home/pietje", "");
    #succeed;

    resetStuff();

    *kv1."asdf" = "bsdf";
    *kv1."bsdf" = "csdf";

    writeLine("stdout", "Adding user <pietje>");
    msiSudoUserAdd("pietje", "", "", "", *kv1)                  ::: msiSudoUserRemove("pietje", "");
    writeLine("stdout", "Adding group <grp-pietje>");
    msiSudoGroupAdd("grp-pietje", "", "", "", "")               ::: msiSudoGroupRemove("grp-pietje", "");
    writeLine("stdout", "Adding user <pietje> to group <grp-pietje>");
    msiSudoGroupMemberAdd("grp-pietje", "pietje", "") ::: msiSudoGroupMemberRemove("grp-pietje", "pietje", "");
    #writeLine("stdout", "Adding user <chris> to group <grp-pietje>");
    #msiSudoGroupMemberAdd("grp-pietje", "chris", "") ::: msiSudoGroupMemberRemove("grp-pietje", "chris", "");

    #writeLine("stdout", "Setting inherit on /tempZone/home/grp-pietje");
    #msiSudoObjAclSet("recursive", "inherit", "", "/tempZone/home/grp-pietje", "");
    writeLine("stdout", "Giving chris own access to /tempZone/home/grp-pietje");
    msiSudoObjAclSet("recursive", "own", "chris", "/tempZone/home/grp-pietje", "");

    msiDataObjCreate("/tempZone/home/grp-pietje/test.txt", "", *fh);
    msiDataObjClose(*fh, *_);

    msiSudoObjAclSet("recursive", "read", "public", "/tempZone/home/grp-pietje", "");

    msiSudoObjAclSet("recursive", "inherit", "", "/tempZone/home/grp-pietje", "");

    msiSudoObjMetaSet("grp-pietje", "-u", "yada", "vijftien", "", "");
    msiSudoObjMetaRemove("grp-pietje", "-u", "", "yada", "vijftien", "", "");

    msiSudoObjMetaAdd("grp-pietje", "-u", "yada", "zestien", "", "");
    msiSudoObjMetaAdd("grp-pietje", "-u", "yada", "zeventien", "hoi", "");
    msiSudoObjMetaAdd("grp-pietje", "-u", "yada", "achttien", "", "");
    msiSudoObjMetaRemove("grp-pietje", "-u", "wildcards", "yada", "%e%tien", "%", "");

    #succeed;

    #msiSudoGroupMemberRemove("grp-pietje", "pietje", "");
    #msiSudoGroupRemove("grp-pietje", "");
    #msiSudoUserRemove("pietje", "");

    resetStuff();
    writeLine("stdout", "Done.");
}

resetStuff() {
    writeLine("stdout", "Resetting stuff");
    writeLine("stdout", "Removing /tempZone/home/grp-pietje/test.txt");
    errorcode(msiSudoObjAclSet("recursive", "own", "chris", "/tempZone/home/grp-pietje", ""));
    errorcode(msiDataObjUnlink("/tempZone/home/grp-pietje/test.txt", *_));
    writeLine("stdout", "Removing inherit from /tempZone/home/grp-pietje");
    errorcode(msiSudoObjAclSet("recursive", "noinherit", "", "/tempZone/home/grp-pietje", ""));
    writeLine("stdout", "Removing user <pietje> from group <grp-pietje>");
    errorcode(msiSudoGroupMemberRemove("grp-pietje", "pietje", ""));
    #writeLine("stdout", "Removing user <chris> from group <grp-pietje>");
    #errorcode(msiSudoGroupMemberRemove("grp-pietje", "chris", ""));
    writeLine("stdout", "Removing group <grp-pietje>");
    errorcode(msiSudoGroupRemove("grp-pietje", ""));
    writeLine("stdout", "Removing user <pietje>");
    errorcode(msiSudoUserRemove("pietje", ""));
}

input null
output ruleExecOut
