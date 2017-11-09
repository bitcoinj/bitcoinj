/*
 * Copyright 2017 Nicola Atzei
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.script;

import java.util.HashMap;
import java.util.Map;

public enum ScriptError {

    SCRIPT_ERR_OK("OK"),
    SCRIPT_ERR_UNKNOWN_ERROR("UNKNOWN_ERROR"),
    SCRIPT_ERR_EVAL_FALSE("EVAL_FALSE"),
    SCRIPT_ERR_OP_RETURN("OP_RETURN"),

    /* Max sizes */
    SCRIPT_ERR_SCRIPT_SIZE("SCRIPT_SIZE"),
    SCRIPT_ERR_PUSH_SIZE("PUSH_SIZE"),
    SCRIPT_ERR_OP_COUNT("OP_COUNT"),
    SCRIPT_ERR_STACK_SIZE("STACK_SIZE"),
    SCRIPT_ERR_SIG_COUNT("SIG_COUNT"),
    SCRIPT_ERR_PUBKEY_COUNT("PUBKEY_COUNT"),

    /* Failed verify operations */
    SCRIPT_ERR_VERIFY("VERIFY"),
    SCRIPT_ERR_EQUALVERIFY("EQUALVERIFY"),
    SCRIPT_ERR_CHECKMULTISIGVERIFY("CHECKMULTISIGVERIFY"),
    SCRIPT_ERR_CHECKSIGVERIFY("CHECKSIGVERIFY"),
    SCRIPT_ERR_NUMEQUALVERIFY("NUMEQUALVERIFY"),

    /* Logical/Format/Canonical errors */
    SCRIPT_ERR_BAD_OPCODE("BAD_OPCODE"),
    SCRIPT_ERR_DISABLED_OPCODE("DISABLED_OPCODE"),
    SCRIPT_ERR_INVALID_STACK_OPERATION("INVALID_STACK_OPERATION"),
    SCRIPT_ERR_INVALID_ALTSTACK_OPERATION("INVALID_ALTSTACK_OPERATION"),
    SCRIPT_ERR_UNBALANCED_CONDITIONAL("UNBALANCED_CONDITIONAL"),

    /* CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY */
    SCRIPT_ERR_NEGATIVE_LOCKTIME("NEGATIVE_LOCKTIME"),
    SCRIPT_ERR_UNSATISFIED_LOCKTIME("UNSATISFIED_LOCKTIME"),

    /* Malleability */
    SCRIPT_ERR_SIG_HASHTYPE("SIG_HASHTYPE"),
    SCRIPT_ERR_SIG_DER("SIG_DER"),
    SCRIPT_ERR_MINIMALDATA("MINIMALDATA"),
    SCRIPT_ERR_SIG_PUSHONLY("SIG_PUSHONLY"),
    SCRIPT_ERR_SIG_HIGH_S("SIG_HIGH_S"),
    SCRIPT_ERR_SIG_NULLDUMMY("SIG_NULLDUMMY"),
    SCRIPT_ERR_PUBKEYTYPE("PUBKEYTYPE"),
    SCRIPT_ERR_CLEANSTACK("CLEANSTACK"),
    SCRIPT_ERR_MINIMALIF("MINIMALIF"),
    SCRIPT_ERR_SIG_NULLFAIL("NULLFAIL"),

    /* softfork safeness */
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS("DISCOURAGE_UPGRADABLE_NOPS"),
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"),

    /* segregated witness */
    SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH("WITNESS_PROGRAM_WRONG_LENGTH"),
    SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY("WITNESS_PROGRAM_WITNESS_EMPTY"),
    SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH("WITNESS_PROGRAM_MISMATCH"),
    SCRIPT_ERR_WITNESS_MALLEATED("WITNESS_MALLEATED"),
    SCRIPT_ERR_WITNESS_MALLEATED_P2SH("WITNESS_MALLEATED_P2SH"),
    SCRIPT_ERR_WITNESS_UNEXPECTED("WITNESS_UNEXPECTED"),
    SCRIPT_ERR_WITNESS_PUBKEYTYPE("WITNESS_PUBKEYTYPE"),

    SCRIPT_ERR_ERROR_COUNT("ERROR_COUNT");

    private final String mnemonic;
    private static final Map<String, ScriptError> mnemonicToScriptErrorMap;

    private ScriptError(String name) {
        this.mnemonic = name;
    }

    static {
        mnemonicToScriptErrorMap = new HashMap<>();
        for (ScriptError err : ScriptError.values()) {
            mnemonicToScriptErrorMap.put(err.getMnemonic(), err);
        }
    }

    public String getMnemonic() {
        return mnemonic;
    }

    public static ScriptError fromMnemonic(String name) {
        ScriptError err = mnemonicToScriptErrorMap.get(name);
        if (err == null)
            throw new IllegalArgumentException(name + " is not a valid name");
        return err;
    }
}
