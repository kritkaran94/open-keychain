/*
 * Copyright (C) 2015 Dominik Schürmann <dominik@dominikschuermann.de>
 * Copyright (C) 2015 Vincent Breitmoser <v.breitmoser@mugenguild.com>
 * Copyright (C) 2015 Adithya Abraham Philip <adithyaphilip@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.sufficientlysecure.keychain.operations;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.util.Pair;

import org.sufficientlysecure.keychain.keyimport.ParcelableEncryptedKeyRing;
import org.sufficientlysecure.keychain.operations.results.ConsolidateResult.WriteKeyRingsResult;
import org.sufficientlysecure.keychain.operations.results.ConsolidateResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.OperationResult;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKey.SecretKeyType;
import org.sufficientlysecure.keychain.pgp.Progressable;
import org.sufficientlysecure.keychain.pgp.WrappedSignature;
import org.sufficientlysecure.keychain.provider.KeychainContract.Certs;
import org.sufficientlysecure.keychain.provider.KeychainContract.KeyRingData;
import org.sufficientlysecure.keychain.provider.KeychainContract.Keys;
import org.sufficientlysecure.keychain.provider.ProviderHelper;
import org.sufficientlysecure.keychain.service.ConsolidateInputParcel;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.ui.util.KeyFormattingUtils;

import java.util.Iterator;

public class ConsolidateOperation extends BaseOperation<ConsolidateInputParcel> {

    public ConsolidateOperation(Context context, ProviderHelper providerHelper, Progressable
            progressable) {
        super(context, providerHelper, progressable);
    }

    @NonNull
    @Override
    public ConsolidateResult execute(ConsolidateInputParcel consolidateInputParcel,
                                     CryptoInputParcel cryptoInputParcel) {
        if (consolidateInputParcel.mConsolidateRecovery) {
            return mProviderHelper.consolidateDatabaseStep2(mProgressable);
        } else {
            return mProviderHelper.consolidateDatabaseStep1(mProgressable);
        }
    }

    public WriteKeyRingsResult writeSecretKeyRingsToDb(Iterator<ParcelableEncryptedKeyRing> it, int num) {
        OperationLog log = new OperationLog();
        int indent = 0;
        ContentResolver contentResolver = mContext.getContentResolver();
        log.add(LogType.MSG_WRITE, indent, num);

        indent += 1;
        while(it.hasNext()) {
            ParcelableEncryptedKeyRing encryptedRing = it.next();
            long masterKeyId = encryptedRing.mMasterKeyId;
            log.add(LogType.MSG_WS, indent, KeyFormattingUtils.convertKeyIdToHex(masterKeyId));
            indent += 1;

            // 1. save secret keyring
            ContentValues values = new ContentValues();
            values.put(KeyRingData.MASTER_KEY_ID, masterKeyId);
            values.put(KeyRingData.KEY_RING_DATA, encryptedRing.mBytes);
            Uri uri = KeyRingData.buildSecretKeyRingUri(masterKeyId);
            if (contentResolver.insert(uri, values) == null) {
                log.add(LogType.MSG_WS_DB_EXCEPTION, indent);
                return new WriteKeyRingsResult(OperationResult.RESULT_ERROR, log);
            }

            // 2. verify self certs
            log.add(LogType.MSG_WS_UPDATING_SELF_CERTS, indent);
            indent += 1;
            uri = Certs.buildCertsUri(masterKeyId);
            values = new ContentValues();
            values.put(Certs.VERIFIED, Certs.VERIFIED_SECRET);
            String where = Certs.KEY_ID_CERTIFIER + "=?" + " AND " + Certs.TYPE + "!=?";
            String[] selectionArgs = new String[] {String.valueOf(masterKeyId),
                    String.valueOf(WrappedSignature.CERTIFICATION_REVOCATION)};
            contentResolver.update(uri, values, where, selectionArgs);
            log.add(LogType.MSG_WS_UPDATED_SELF_CERTS, indent);
            indent -= 1;

            // 3. insert subkey info
            uri = Keys.buildKeysUri(masterKeyId);

            // first, mark all keys as not available
            values = new ContentValues();
            values.put(Keys.HAS_SECRET, SecretKeyType.GNU_DUMMY.getNum());
            contentResolver.update(uri, values, null, null);

            // then, mark exactly the keys we have available
            log.add(LogType.MSG_WS_WRITING_SUBKEY_DATA, indent);
            indent += 1;
            for (Pair<Long, Integer> subKeyIdWithType : encryptedRing.mSubKeyIdsAndType) {
                long id = subKeyIdWithType.first;
                int subKeyType = subKeyIdWithType.second;
                values.put(Keys.HAS_SECRET, subKeyType);
                int upd = contentResolver.update(uri, values, Keys.KEY_ID + " = ?",
                        new String[]{Long.toString(id)});
                if (upd == 1) {
                    switch (SecretKeyType.values()[subKeyType]) {
                        case PASSPHRASE:
                            log.add(LogType.MSG_WS_SUBKEY_OK, indent,
                                    KeyFormattingUtils.convertKeyIdToHex(id)
                            );
                            break;
                        case PASSPHRASE_EMPTY:
                            log.add(LogType.MSG_WS_SUBKEY_EMPTY, indent,
                                    KeyFormattingUtils.convertKeyIdToHex(id)
                            );
                            break;
                        case PIN:
                            log.add(LogType.MSG_WS_SUBKEY_PIN, indent,
                                    KeyFormattingUtils.convertKeyIdToHex(id)
                            );
                            break;
                        case GNU_DUMMY:
                            log.add(LogType.MSG_WS_SUBKEY_STRIPPED, indent,
                                    KeyFormattingUtils.convertKeyIdToHex(id)
                            );
                            break;
                        case DIVERT_TO_CARD:
                            log.add(LogType.MSG_WS_SUBKEY_DIVERT, indent,
                                    KeyFormattingUtils.convertKeyIdToHex(id)
                            );
                            break;
                    }
                } else {
                    log.add(LogType.MSG_WS_SUBKEY_NONEXISTENT, indent,
                            KeyFormattingUtils.convertKeyIdToHex(id)
                    );
                }
            }
            indent -= 1;

            // this implicitly leaves all keys which were not in the secret key ring
            // with has_secret = 1
            log.add(LogType.MSG_WS_SUCCESS, indent);
        }
        indent -= 1;
        log.add(LogType.MSG_WRITE_SUCCESS, indent);
        return new WriteKeyRingsResult(OperationResult.RESULT_OK, log);
    }
}
