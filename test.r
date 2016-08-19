test {
    #*errcode = errormsg(msiGaGroupAdd("grp-pizza"), *errmsg);
    *kv1."." = "1";
    *kv1."hoi" = ":)";
    *kv1."werkt dit?" = "blijkbaar, ja.";
    #*kv2."." = "";

    resetStuff();

    writeLine("stdout", "Adding user <pietje>");
    msiSudoUserAdd("pietje", "", "", "", "")                      ::: msiSudoUserRemove("pietje", "");
    writeLine("stdout", "Adding group <grp-pietje>");
    msiSudoGroupAdd("grp-pietje", "", "", "", *kv1)               ::: msiSudoGroupRemove("grp-pietje", "");
    writeLine("stdout", "Adding user <pietje> to group <grp-pietje>");
    msiSudoGroupMemberAdd("grp-pietje", "pietje", "") ::: msiSudoGroupMemberRemove("grp-pietje", "pietje", "");
    #writeLine("stdout", "Adding user <chris> to group <grp-pietje>");
    #msiSudoGroupMemberAdd("grp-pietje", "chris", "") ::: msiSudoGroupMemberRemove("grp-pietje", "chris", "");

    #writeLine("stdout", "Setting inherit on /tempZone/home/grp-pietje");
    #msiSudoObjAclSet(1, "inherit", "", "/tempZone/home/grp-pietje", "");
    writeLine("stdout", "Giving chris own access to /tempZone/home/grp-pietje");
    msiSudoObjAclSet(1, "own", "chris", "/tempZone/home/grp-pietje", "");

    msiDataObjCreate("/tempZone/home/grp-pietje/test.txt", "", *fh);
    msiDataObjClose(*fh, *_);

    msiSudoObjAclSet(1, "read", "public", "/tempZone/home/grp-pietje", "");

    msiSudoObjAclSet(1, "inherit", "", "/tempZone/home/grp-pietje", "");

    msiSudoObjMetaSet("grp-pietje", "-u", "yada", "vijftien", "", "");
    msiSudoObjMetaRemove("grp-pietje", "-u", 0, "yada", "vijftien", "", "");

    msiSudoObjMetaAdd("grp-pietje", "-u", "yada", "zestien", "", "");
    msiSudoObjMetaAdd("grp-pietje", "-u", "yada", "zeventien", "hoi", "");
    msiSudoObjMetaAdd("grp-pietje", "-u", "yada", "achttien", "", "");
    msiSudoObjMetaRemove("grp-pietje", "-u", 1, "yada", "%e%tien", "%", "");

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
    errorcode(msiSudoObjAclSet(1, "own", "chris", "/tempZone/home/grp-pietje", ""));
    errorcode(msiDataObjUnlink("/tempZone/home/grp-pietje/test.txt", *_));
    writeLine("stdout", "Removing inherit from /tempZone/home/grp-pietje");
    errorcode(msiSudoObjAclSet(1, "noinherit", "", "/tempZone/home/grp-pietje", ""));
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
