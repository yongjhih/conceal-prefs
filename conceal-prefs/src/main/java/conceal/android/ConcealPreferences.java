/*
 * Copyright (C) 2017, Andrew Chen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package conceal.android;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;
import android.util.Log;

import com.facebook.android.crypto.keychain.AndroidConceal;
import com.facebook.android.crypto.keychain.SharedPrefsBackedKeyChain;
import com.facebook.crypto.Crypto;
import com.facebook.crypto.CryptoConfig;
import com.facebook.crypto.Entity;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.keychain.KeyChain;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 *
 */
public class ConcealPreferences implements SharedPreferences {
    private SharedPreferences prefs;
    private Crypto crypto;
    private Entity entity;
    //private static final String ENTITY_PREFS = new String(Base64.decode("cHJlZnM=", Base64.NO_WRAP), "UTF-8");
    private static final String ENTITY_PREFS = "prefs";

    public ConcealPreferences(@NonNull Context context) {
        this(context, PreferenceManager.getDefaultSharedPreferences(context));
    }

    public ConcealPreferences(@NonNull Context context, @NonNull SharedPreferences prefs) {
        this(prefs, new SharedPrefsBackedKeyChain(context, CryptoConfig.KEY_256));
    }

    public ConcealPreferences(@NonNull SharedPreferences prefs, @NonNull KeyChain keyChain) {
        this(prefs, AndroidConceal.get().createDefaultCrypto(keyChain));
    }

    public ConcealPreferences(@NonNull SharedPreferences prefs, @NonNull Crypto crypto) {
        this.prefs = prefs;
        this.crypto = crypto;
        this.entity = Entity.create(ENTITY_PREFS);
    }

    @Override
    public Map<String, ?> getAll() {
        final Map<String, ?> encryptedMap = prefs.getAll();
        final Map<String, String> decryptedMap = new HashMap<>(encryptedMap.size());
        for (Map.Entry<String, ?> entry : encryptedMap.entrySet()) {
            Object cipherText = entry.getValue();
            decryptedMap.put(entry.getKey(), decrypt(cipherText.toString(), entry.getValue().toString()));
        }
        return decryptedMap;
    }

    @Override
    public String getString(@NonNull String key, String defValue) {
        return decrypt(prefs.getString(key, null), defValue);
    }

    @Nullable
    private String decrypt(@Nullable String value, @Nullable String defValue) {
        if (!crypto.isAvailable()) { throw new IllegalStateException(); }

        if (value == null) return defValue;
        try {
            return new String(Base64.decode(crypto.decrypt(value.getBytes(), entity), Base64.NO_WRAP));
        } catch (KeyChainException | CryptoInitializationException | IOException e) {
            e.printStackTrace();
        }
        return defValue;
    }

    @Nullable
    private String decrypt(@Nullable String value) {
        return decrypt(value, null);
    }

    @Override
    @TargetApi(Build.VERSION_CODES.HONEYCOMB)
    public Set<String> getStringSet(@NonNull String key, Set<String> defValues) {
        Set<String> value = prefs.getStringSet(key, null);

        if (value == null) return defValues;
        Set<String> to = new HashSet<>(value.size());
        for (String entry : value) {
            to.add(decrypt(entry));
        }
        return to;
    }

    @Override
    public int getInt(@NonNull String key, int defValue) {
        try {
            String value = decrypt(key, null);
            return (value == null) ? defValue : Integer.parseInt(value);
        } catch (NumberFormatException e) {
            e.printStackTrace();
        }
        return defValue;
    }

    @Override
    public long getLong(@NonNull String key, long defValue) {
        try {
            String value = decrypt(key, null);
            return (value == null) ? defValue : Long.parseLong(value);
        } catch (NumberFormatException e) {
            e.printStackTrace();
        }
        return defValue;
    }

    @Override
    public float getFloat(@NonNull String key, float defValue) {
        try {
            String value = decrypt(key, null);
            return (value == null) ? defValue : Float.parseFloat(value);
        } catch (NumberFormatException e) {
            e.printStackTrace();
        }
        return defValue;
    }

    @Override
    public boolean getBoolean(@NonNull String key, boolean defValue) {
        try {
            String value = decrypt(key, null);
            return (value == null) ? defValue : Boolean.parseBoolean(value);
        } catch (NumberFormatException e) {
            e.printStackTrace();
        }
        return defValue;
    }

    @Override
    public boolean contains(String key) {
        return prefs.contains(key);
    }

    private Editor editor;

    // TODO: Avoid circular
    @Override
    public Editor edit() {
        if (editor == null) editor = new Editor(prefs.edit(), crypto, entity);
        return editor;
    }

    @Override
    public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        prefs.registerOnSharedPreferenceChangeListener(listener);
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        prefs.unregisterOnSharedPreferenceChangeListener(listener);
    }

    public static class Editor implements SharedPreferences.Editor {
        private SharedPreferences.Editor editor;
        private Crypto crypto;
        private Entity entity;

        public Editor(@NonNull SharedPreferences.Editor editor, @NonNull Crypto crypto, @NonNull Entity entity) {
            this.editor = editor;
            this.crypto = crypto;
            this.entity = entity;
        }

        @Nullable
        private String encrypt(@Nullable String value) {
            if (!crypto.isAvailable()) { throw new IllegalStateException(); }

            if (value == null) return null;

            try {
                return Base64.encodeToString(crypto.encrypt(value.getBytes(), entity), Base64.NO_WRAP);
            } catch (KeyChainException | CryptoInitializationException | IOException e) {
                e.printStackTrace();
            }
            return null;
        }

        @Override
        @NonNull
        public SharedPreferences.Editor putString(String key, String value) {
            editor.putString(key, encrypt(value)); // TODO encrypt key
            return this;
        }

        @Override
        @NonNull
        @TargetApi(Build.VERSION_CODES.HONEYCOMB)
        public SharedPreferences.Editor putStringSet(@NonNull String key, @Nullable final Set<String> values) {
            if (values == null) {
                editor.putStringSet(key, null);
                return this;
            }

            Set<String> to = new HashSet<>(values.size());
            for (String entry : values) {
                to.add(encrypt(entry));
            }
            editor.putStringSet(key, to);
            return this;
        }

        @Override
        @NonNull
        public SharedPreferences.Editor putInt(String key, int value) {
            editor.putString(key, encrypt(String.valueOf(value)));
            return this;
        }

        @Override
        @NonNull
        public SharedPreferences.Editor putLong(String key, long value) {
            editor.putString(key, encrypt(String.valueOf(value)));
            return this;
        }

        @Override
        @NonNull
        public SharedPreferences.Editor putFloat(String key, float value) {
            editor.putString(key, encrypt(String.valueOf(value)));
            return this;
        }

        @Override
        @NonNull
        public SharedPreferences.Editor putBoolean(String key, boolean value) {
            editor.putString(key, encrypt(String.valueOf(value)));
            return this;
        }

        @Override
        @NonNull
        public SharedPreferences.Editor remove(String key) {
            editor.remove(key);
            return this;
        }

        @Override
        @NonNull
        public SharedPreferences.Editor clear() {
            editor.clear();
            return this;
        }

        @Override
        public boolean commit() {
            return editor.commit();
        }

        @Override
        public void apply() {
            editor.apply();
        }
    }
}
