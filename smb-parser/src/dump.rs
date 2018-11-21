/* Copyright (C) 2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

use std::str;
use std::string::String;
use serde_json::Value;
use serde_json::map::Map;
use smb::*;
use smb1::*;
use smb2::*;
use dcerpc::*;
use funcs::*;

#[cfg(not(feature = "debug"))]
fn debug_add_progress(_js: &mut Map<String, Value>, _tx: &SMBTransaction) { }

#[cfg(feature = "debug")]
fn debug_add_progress(js: &mut Map, tx: &SMBTransaction) {
    js.insert("request_done".to_owned(), Value::Bool(tx.request_done));
    js.insert("response_done".to_owned(), Value::Bool(tx.request_done));
}

/// take in a file GUID (16 bytes) or FID (2 bytes). Also deal
/// with our frankenFID (2 bytes + 4 user_id)
fn fuid_to_string(fuid: &Vec<u8>) -> String {
    let fuid_len = fuid.len();
    if fuid_len == 16 {
        guid_to_string(fuid)
    } else if fuid_len == 2 {
        format!("{:02x}{:02x}", fuid[1], fuid[0])
    } else if fuid_len == 6 {
        let pure_fid = &fuid[0..2];
        format!("{:02x}{:02x}", pure_fid[1], pure_fid[0])
    } else {
        "".to_string()
    }
}

fn guid_to_string(guid: &Vec<u8>) -> String {
    if guid.len() == 16 {
        let output = format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                guid[3],  guid[2],  guid[1],  guid[0],
                guid[5],  guid[4],  guid[7],  guid[6],
                guid[9],  guid[8],  guid[11], guid[10],
                guid[15], guid[14], guid[13], guid[12]);
        output
    } else {
        "".to_string()
    }
}

fn smb_common_header(state: &SMBState, tx: &SMBTransaction) -> Value
{
    let mut js = Map::new();
    js.insert("id".to_owned(), Value::Number(tx.id.into()));

    if state.dialect != 0 {
        let dialect = smb2_dialect_string(state.dialect);
        js.insert("dialect".to_owned(), Value::String(dialect));
    } else {
        let dialect = match &state.dialect_vec {
            &Some(ref d) => str::from_utf8(&d).unwrap_or("invalid"),
            &None        => "unknown",
        };
        js.insert("dialect".to_owned(), Value::String(dialect.to_owned()));
    }

    match tx.vercmd.get_version() {
        1 => {
            let (ok, cmd) = tx.vercmd.get_smb1_cmd();
            if ok {
                js.insert("command".to_owned(), Value::String(smb1_command_string(cmd)));
            }
        },
        2 => {
            let (ok, cmd) = tx.vercmd.get_smb2_cmd();
            if ok {
                js.insert("command".to_owned(), Value::String(smb2_command_string(cmd)));
            }
        },
        _ => { },
    }

    match tx.vercmd.get_ntstatus() {
        (true, ntstatus) => {
            let status = smb_ntstatus_string(ntstatus);
            js.insert("status".to_owned(), Value::String(status));
            let status_hex = format!("0x{:x}", ntstatus);
            js.insert("status_code".to_owned(), Value::String(status_hex));
        },
        (false, _) => {
            match tx.vercmd.get_dos_error() {
                (true, errclass, errcode) => {
                    match errclass {
                        1 => { // DOSERR
                            let status = smb_dos_error_string(errcode);
                            js.insert("status".to_owned(), Value::String(status));
                        },
                        2 => { // SRVERR
                            let status = smb_srv_error_string(errcode);
                            js.insert("status".to_owned(), Value::String(status));
                        }
                        _ => {
                            let s = format!("UNKNOWN_{:02x}_{:04x}", errclass, errcode);
                            js.insert("status".to_owned(), Value::String(s));
                        },
                    }
                    let status_hex = format!("0x{:04x}", errcode);
                    js.insert("status_code".to_owned(), Value::String(status_hex));
                },
                (_, _, _) => {
                },
            }
        },
    }


    js.insert("session_id".to_owned(), Value::Number(tx.hdr.ssn_id.into()));
    js.insert("tree_id".to_owned(), Value::Number(tx.hdr.tree_id.into()));

    debug_add_progress(&mut js, tx);

    match tx.type_data {
        Some(SMBTransactionTypeData::SESSIONSETUP(ref x)) => {
            if let Some(ref ntlmssp) = x.ntlmssp {
                let mut jsd = Map::new();
                let domain = String::from_utf8_lossy(&ntlmssp.domain);
                jsd.insert("domain".to_owned(), Value::String(domain.into_owned()));

                let user = String::from_utf8_lossy(&ntlmssp.user);
                jsd.insert("user".to_owned(), Value::String(user.into_owned()));

                let host = String::from_utf8_lossy(&ntlmssp.host);
                jsd.insert("host".to_owned(), Value::String(host.into_owned()));

                if let Some(ref v) = ntlmssp.version {
                    jsd.insert("version".to_owned(), Value::String(v.to_string()));
                }

                js.insert("ntlmssp".to_owned(), Value::Object(jsd));
            }

            if let Some(ref ticket) = x.krb_ticket {
                let mut jsd = Map::new();
                jsd.insert("realm".to_owned(), Value::String(ticket.realm.0.to_owned()));
                let mut jsa = Vec::new();
                for sname in ticket.sname.name_string.iter() {
                    jsa.push(Value::String(sname.to_owned()));
                }
                jsd.insert("snames".to_owned(), Value::Array(jsa));
                js.insert("kerberos".to_owned(), Value::Object(jsd));
            }

            match x.request_host {
                Some(ref r) => {
                    let mut jsd = Map::new();
                    let os = String::from_utf8_lossy(&r.native_os);
                    jsd.insert("native_os".to_owned(), Value::String(os.into_owned()));
                    let lm = String::from_utf8_lossy(&r.native_lm);
                    jsd.insert("native_lm".to_owned(), Value::String(lm.into_owned()));
                    js.insert("request".to_owned(), Value::Object(jsd));
                },
                None => { },
            }
            match x.response_host {
                Some(ref r) => {
                    let mut jsd = Map::new();
                    let os = String::from_utf8_lossy(&r.native_os);
                    jsd.insert("native_os".to_owned(), Value::String(os.into_owned()));
                    let lm = String::from_utf8_lossy(&r.native_lm);
                    jsd.insert("native_lm".to_owned(), Value::String(lm.into_owned()));
                    js.insert("response".to_owned(), Value::Object(jsd));
                },
                None => { },
            }
        },
        Some(SMBTransactionTypeData::CREATE(ref x)) => {
            let mut name_raw = x.filename.to_vec();
            name_raw.retain(|&i|i != 0x00);
            if name_raw.len() > 0 {
                let name = String::from_utf8_lossy(&name_raw);
                if x.directory {
                    js.insert("directory".to_owned(), Value::String(name.into_owned()));
                } else {
                    js.insert("filename".to_owned(), Value::String(name.into_owned()));
                }
            } else {
                // name suggestion from Bro
                js.insert("filename".to_owned(), Value::String("<share_root>".to_owned()));
            }
            match x.disposition {
                0 => { js.insert("disposition".to_owned(), Value::String("FILE_SUPERSEDE".to_owned())); },
                1 => { js.insert("disposition".to_owned(), Value::String("FILE_OPEN".to_owned())); },
                2 => { js.insert("disposition".to_owned(), Value::String("FILE_CREATE".to_owned())); },
                3 => { js.insert("disposition".to_owned(), Value::String("FILE_OPEN_IF".to_owned())); },
                4 => { js.insert("disposition".to_owned(), Value::String("FILE_OVERWRITE".to_owned())); },
                5 => { js.insert("disposition".to_owned(), Value::String("FILE_OVERWRITE_IF".to_owned())); },
                _ => { js.insert("disposition".to_owned(), Value::String("UNKNOWN".to_owned())); },
            }
            if x.delete_on_close {
                js.insert("access".to_owned(), Value::String("delete on close".to_owned()));
            } else {
                js.insert("access".to_owned(), Value::String("normal".to_owned()));
            }

            // field names inspired by Bro
            js.insert("created".to_owned(), Value::Number((x.create_ts as u64).into()));
            js.insert("accessed".to_owned(), Value::Number((x.last_access_ts as u64).into()));
            js.insert("modified".to_owned(), Value::Number((x.last_write_ts as u64).into()));
            js.insert("changed".to_owned(), Value::Number((x.last_change_ts as u64).into()));
            js.insert("size".to_owned(), Value::Number((x.size).into()));

            let gs = fuid_to_string(&x.guid);
            js.insert("fuid".to_owned(), Value::String(gs));
        },
        Some(SMBTransactionTypeData::NEGOTIATE(ref x)) => {
            if x.smb_ver == 1 {
                let mut jsa = Vec::new();
                for d in &x.dialects {
                    let dialect = String::from_utf8_lossy(&d);
                    jsa.push(Value::String(dialect.into_owned()));
                }
                js.insert("client_dialects".to_owned(), Value::Array(jsa));
            } else if x.smb_ver == 2 {
                let mut jsa = Vec::new();
                for d in &x.dialects2 {
                    let dialect = String::from_utf8_lossy(&d);
                    jsa.push(Value::String(dialect.into_owned()));
                }
                js.insert("client_dialects".to_owned(), Value::Array(jsa));
            }

            if let Some(ref g) = x.client_guid {
                js.insert("client_guid".to_owned(), Value::String(guid_to_string(g)));
            }

            js.insert("server_guid".to_owned(), Value::String(guid_to_string(&x.server_guid)));
        },
        Some(SMBTransactionTypeData::TREECONNECT(ref x)) => {
            js.insert("tree_id".to_owned(), Value::Number((x.tree_id as u64).into()));

            let share_name = String::from_utf8_lossy(&x.share_name);
            if x.is_pipe {
                js.insert("named_pipe".to_owned(), Value::String(share_name.into_owned()));
            } else {
                js.insert("share".to_owned(), Value::String(share_name.into_owned()));
            }

            // handle services
            if tx.vercmd.get_version() == 1 {
                let mut jsd = Map::new();

                if let Some(ref s) = x.req_service {
                    let serv = String::from_utf8_lossy(&s);
                    jsd.insert("request".to_owned(), Value::String(serv.into_owned()));
                }
                if let Some(ref s) = x.res_service {
                    let serv = String::from_utf8_lossy(&s);
                    jsd.insert("response".to_owned(), Value::String(serv.into_owned()));
                }
                js.insert("service".to_owned(), Value::Object(jsd));

            // share type only for SMB2
            } else {
                match x.share_type {
                    1 => { js.insert("share_type".to_owned(), Value::String("FILE".to_owned())); },
                    2 => { js.insert("share_type".to_owned(), Value::String("PIPE".to_owned())); },
                    3 => { js.insert("share_type".to_owned(), Value::String("PRINT".to_owned())); },
                    _ => { js.insert("share_type".to_owned(), Value::String("UNKNOWN".to_owned())); },
                }
            }
        },
        Some(SMBTransactionTypeData::FILE(ref x)) => {
            let file_name = String::from_utf8_lossy(&x.file_name);
            js.insert("filename".to_owned(), Value::String(file_name.into_owned()));
            let share_name = String::from_utf8_lossy(&x.share_name);
            js.insert("share".to_owned(), Value::String(share_name.into_owned()));
            let gs = fuid_to_string(&x.fuid);
            js.insert("fuid".to_owned(), Value::String(gs));
        },
        Some(SMBTransactionTypeData::RENAME(ref x)) => {
            if tx.vercmd.get_version() == 2 {
                let mut jsd = Map::new();
                jsd.insert("class".to_owned(), Value::String("FILE_INFO".to_owned()));
                jsd.insert("info_level".to_owned(), Value::String("SMB2_FILE_RENAME_INFO".to_owned()));
                js.insert("set_info".to_owned(), Value::Object(jsd));
            }

            let mut jsd = Map::new();
            let file_name = String::from_utf8_lossy(&x.oldname);
            jsd.insert("from".to_owned(), Value::String(file_name.into_owned()));
            let file_name = String::from_utf8_lossy(&x.newname);
            jsd.insert("to".to_owned(), Value::String(file_name.into_owned()));
            js.insert("rename".to_owned(), Value::Object(jsd));
            let gs = fuid_to_string(&x.fuid);
            js.insert("fuid".to_owned(), Value::String(gs));
        },
        Some(SMBTransactionTypeData::DCERPC(ref x)) => {
            let mut jsd = Map::new();
            if x.req_set {
                jsd.insert("request".to_owned(), Value::String(dcerpc_type_string(x.req_cmd)));
            } else {
                jsd.insert("request".to_owned(), Value::String("REQUEST_LOST".to_owned()));
            }
            if x.res_set {
                jsd.insert("response".to_owned(), Value::String(dcerpc_type_string(x.res_cmd)));
            } else {
                jsd.insert("response".to_owned(), Value::String("UNREPLIED".to_owned()));
            }
            if x.req_set {
                match x.req_cmd {
                    DCERPC_TYPE_REQUEST => {
                        jsd.insert("opnum".to_owned(), Value::Number((x.opnum as u64).into()));
                        let mut req = Map::new();
                        req.insert("frag_cnt".to_owned(), Value::Number((x.frag_cnt_ts as u64).into()));
                        req.insert("stub_data_size".to_owned(), Value::Number((x.stub_data_ts.len() as u64).into()));
                        jsd.insert("req".to_owned(), Value::Object(req));
                    },
                    DCERPC_TYPE_BIND => {
                        match state.dcerpc_ifaces {
                            Some(ref ifaces) => {
                                let mut jsa = Vec::new();
                                for i in ifaces {
                                    let mut jso = Map::new();
                                    let ifstr = dcerpc_uuid_to_string(&i);
                                    jso.insert("uuid".to_owned(), Value::String(ifstr));
                                    let vstr = format!("{}.{}", i.ver, i.ver_min);
                                    jso.insert("version".to_owned(), Value::String(vstr));

                                    if i.acked {
                                        jso.insert("ack_result".to_owned(), Value::Number((i.ack_result as u64).into()));
                                        jso.insert("ack_reason".to_owned(), Value::Number((i.ack_reason as u64).into()));
                                    }

                                    jsa.push(Value::Object(jso));
                                }

                                jsd.insert("interfaces".to_owned(), Value::Array(jsa));
                            },
                            _ => {},
                        }
                    },
                    _ => {},
                }
            }
            if x.res_set {
                match x.res_cmd {
                    DCERPC_TYPE_RESPONSE => {
                        let mut res = Map::new();
                        res.insert("frag_cnt".to_owned(), Value::Number((x.frag_cnt_tc as u64).into()));
                        res.insert("stub_data_size".to_owned(), Value::Number((x.stub_data_tc.len() as u64).into()));
                        jsd.insert("res".to_owned(), Value::Object(res));
                    },
                    // we don't handle BINDACK w/o BIND
                    _ => {},
                }
            }
            jsd.insert("call_id".to_owned(), Value::Number((x.call_id as u64).into()));
            js.insert("dcerpc".to_owned(), Value::Object(jsd));
        }
        Some(SMBTransactionTypeData::IOCTL(ref x)) => {
            js.insert("function".to_owned(), Value::String(fsctl_func_to_string(x.func)));
        },
        Some(SMBTransactionTypeData::SETFILEPATHINFO(ref x)) => {
            let mut name_raw = x.filename.to_vec();
            name_raw.retain(|&i|i != 0x00);
            if name_raw.len() > 0 {
                let name = String::from_utf8_lossy(&name_raw);
                js.insert("filename".to_owned(), Value::String(name.into_owned()));
            } else {
                // name suggestion from Bro
                js.insert("filename".to_owned(), Value::String("<share_root>".to_owned()));
            }
            if x.delete_on_close {
                js.insert("access".to_owned(), Value::String("delete on close".to_owned()));
            } else {
                js.insert("access".to_owned(), Value::String("normal".to_owned()));
            }

            match x.subcmd {
                8 => {
                    js.insert("subcmd".to_owned(), Value::String("SET_FILE_INFO".to_owned()));
                },
                6 => {
                    js.insert("subcmd".to_owned(), Value::String("SET_PATH_INFO".to_owned()));
                },
                _ => { },
            }

            match x.loi {
                1013 => { // Set Disposition Information
                    js.insert("level_of_interest".to_owned(), Value::String("Set Disposition Information".to_owned()));
                },
                _ => { },
            }

            let gs = fuid_to_string(&x.fid);
            js.insert("fuid".to_owned(), Value::String(gs));
        },
        _ => {  },
    }
    return Value::Object(js);
}
