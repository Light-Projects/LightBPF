# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

def str_shortcut(filter_str: str) -> str:
    new = qinq(filter_str)
    return new

def qinq(filter_str: str) -> str:
    return filter_str.replace("qinq","vlan and vlan")


