package org.sufficientlysecure.keychain.util;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.Pair;
import org.sufficientlysecure.keychain.KeychainApplication;

import java.util.ArrayList;

public class KeyringPassphrases implements Parcelable {

    public final long mMasterKeyId;
    public final ArrayList<Pair<Long, Passphrase>> mSubkeyPassphrases;

    public KeyringPassphrases(long masterKeyId) {
        mMasterKeyId = masterKeyId;
        mSubkeyPassphrases = new ArrayList<>();
    }

    public Passphrase getLastPassphrase() {
        if (mSubkeyPassphrases.size() > 0) {
            return mSubkeyPassphrases.get(mSubkeyPassphrases.size() - 1).second;
        } else {
            return null;
        }
    }

    public boolean subKeysHaveSinglePassphrase() {
        if (mSubkeyPassphrases.size() < 2) {
            return true;
        } else {
            Passphrase previous = null;
            for(Pair<Long, Passphrase> passPair : mSubkeyPassphrases) {
                Passphrase current = passPair.second;
                if(previous != null && !current.equals(previous)) {
                    return false;
                }
                previous = current;
            }
            return true;
        }
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel parcel, int flags) {
        parcel.writeLong(mMasterKeyId);
        parcel.writeInt(mSubkeyPassphrases.size());
        for(Pair<Long, Passphrase> passPair : mSubkeyPassphrases) {
            parcel.writeLong(passPair.first);
            parcel.writeParcelable(passPair.second, 0);
        }
    }

    private KeyringPassphrases(Parcel source) {
        mMasterKeyId = source.readLong();
        mSubkeyPassphrases = new ArrayList<>();
        int arrayCount = source.readInt();
        for (int i = 0; i < arrayCount; i++) {
            long id = source.readLong();
            Passphrase passphrase = source.readParcelable(Passphrase.class.getClassLoader());
            mSubkeyPassphrases.add(new Pair<>(id, passphrase));
        }
    }

    public static final Creator<KeyringPassphrases> CREATOR =
            new Creator<KeyringPassphrases>() {
                @Override
                public KeyringPassphrases createFromParcel(Parcel parcel) {
                    return new KeyringPassphrases(parcel);
                }

                @Override
                public KeyringPassphrases[] newArray(int i) {
                    return new KeyringPassphrases[i];
                }
            };

}
