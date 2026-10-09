import java.lang.reflect.Field;
import java.lang.reflect.Method;

import kotlin.Pair;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.BuildersKt;
import kotlinx.coroutines.CoroutineScope;

/**
 * Bifrost 2.1.4'un kendi CryptUtils.getV4Key fonksiyonunu JVM'de calistirir.
 * getV4Key kendi icinde: GenerateNonce + BinaryInform(retry'li) + LATEST_FW_VERSION/
 * LOGIC_VALUE_FACTORY cikarimi + logiccheck + md5 -> AES-128 anahtari.
 * Boylece Python transport katmanindaki (TLS/header fingerprint) 401 problemi
 * tamamen devre-disi kalir — ag trafigi Bifrost'un ktor yolu ile gider.
 *
 * Cikti satirlari (script tarafindan parse edilir):
 *   BINARYINFO=... (crc/size/version)
 *   AESKEY=<hex>
 *   KEYVER=<version>
 */
public class BifrostKey {
    static class EmptyCont implements Continuation<Object> {
        public CoroutineContext getContext() { return EmptyCoroutineContext.INSTANCE; }
        public void resumeWith(Object result) {}
    }

    static Object runSuspend(SuspendCall body) {
        try {
            return BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE,
                    new Function2<CoroutineScope, Continuation<Object>, Object>() {
                        @Override public Object invoke(CoroutineScope scope, Continuation<Object> cont) {
                            try { return body.run(cont); }
                            catch (Exception e) { throw new RuntimeException(e); }
                        }
                    });
        } catch (InterruptedException e) { throw new RuntimeException(e); }
    }

    interface SuspendCall { Object run(Continuation<Object> cont) throws Exception; }

    static Object call(Object obj, String name, Class<?>[] types, Object[] args) throws Exception {
        Method m;
        try { m = obj.getClass().getMethod(name, types); }
        catch (NoSuchMethodException e) {
            m = obj.getClass().getDeclaredMethod(name, types);
            m.setAccessible(true);
        }
        return m.invoke(obj, args);
    }

    static Object getField(Object inst, String name) throws Exception {
        Field f = inst.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(inst);
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        String fw     = "A715FXXSBDXB1/A715FOXMBDXB1/A715FXXSBDXB1/A715FXXSBDXB1";
        String model  = "SM-A715F";
        String region = "DBT";
        String imei   = "350000029442064";

        // ---------- 1) BinaryInform: dosya bilgisi (CRC/size) — BifrostRun paritesi ----------
        Class<?> reqEnumCls = Class.forName("tk.zwander.common.tools.FusClient$Request");
        Object genNonce = null, binInform = null;
        for (Object e : reqEnumCls.getEnumConstants()) {
            String n = ((Enum<?>) e).name();
            if (n.equals("GENERATE_NONCE")) genNonce = e;
            if (n.equals("BINARY_INFORM"))  binInform = e;
        }
        if (genNonce == null || binInform == null) throw new IllegalStateException("Request enum bulunamadi");

        Class<?> fusCls = Class.forName("tk.zwander.common.tools.FusClient");
        Object fus = fusCls.getField("INSTANCE").get(null);

        Method makeReq = null;
        for (Method m : fus.getClass().getDeclaredMethods()) {
            if (m.getName().equals("makeReq") && m.getParameterCount() == 5) {
                makeReq = m; m.setAccessible(true);
            }
        }
        if (makeReq == null) throw new IllegalStateException("makeReq bulunamadi");

        // Lambda yakalamasi icin final kopyalar (loop-assign sonrasi)
        final Object gNonce = genNonce, bInform = binInform;
        final Method mReq = makeReq;

        // Oturum ac (GenerateNonce)
        runSuspend(cont -> mReq.invoke(fus, gNonce, "", null, true, cont));
        Object nonce = getField(fus, "nonce");
        System.out.println("nonce = " + nonce);

        // BinaryInform XML (2.1.4 kendi uretimi, byte-for-byte)
        Class<?> reqCls = Class.forName("tk.zwander.common.tools.Request");
        Object req = reqCls.getField("INSTANCE").get(null);
        Class<?>[] cbiTypes = {String.class, String.class, String.class, String.class, String.class, boolean.class};
        final String xml = (String) call(req, "createBinaryInform", cbiTypes,
                new Object[]{fw, model, region, nonce, imei, false});

        Object resp = runSuspend(cont -> mReq.invoke(fus, bInform, xml, null, false, cont));
        String body = String.valueOf(resp);
        System.out.println("--- BinaryInform body (ilk 2000 karakter) ---");
        System.out.println(body.substring(0, Math.min(2000, body.length())));

        // ---------- 2) getV4Key: anahtar turetimi (Bifrost'un kendi yolu) ----------
        Class<?> cuCls = Class.forName("tk.zwander.common.tools.CryptUtils");
        Object cu = cuCls.getField("INSTANCE").get(null);

        Method getV4Key = null;
        for (Method m : cu.getClass().getDeclaredMethods()) {
            if (m.getName().equals("getV4Key") && m.getParameterCount() == 8) {
                getV4Key = m; m.setAccessible(true);
            }
        }
        if (getV4Key == null) throw new IllegalStateException("getV4Key bulunamadi");
        final Method g4 = getV4Key;

        // Decrypter yolu: legacy=false (Smart uclari), includeNonce=false, tries=3
        Object result;
        try {
            result = runSuspend(cont ->
                    g4.invoke(cu, fw, model, region, imei, 3, false, false, cont));
        } catch (RuntimeException e) {
            System.out.println("getV4Key HATA (smart varyanti):");
            e.printStackTrace(System.out);
            if (e.getCause() != null) e.getCause().printStackTrace(System.out);
            // Alternatif: legacy endpoint + includeNonce
            try {
                result = runSuspend(cont ->
                        g4.invoke(cu, fw, model, region, imei, 3, true, true, cont));
                System.out.println("(legacy varyanti ile basari)");
            } catch (RuntimeException e2) {
                System.out.println("getV4Key HATA (legacy varyanti):");
                e2.printStackTrace(System.out);
                if (e2.getCause() != null) e2.getCause().printStackTrace(System.out);
                return;
            }
        }

        Pair<?, ?> pair = (Pair<?, ?>) result;
        byte[] key = (byte[]) pair.getFirst();
        String ver = String.valueOf(pair.getSecond());

        System.out.println("AESKEY=" + hex(key));
        System.out.println("KEYVER=" + ver);
        System.out.println("KEYLEN=" + key.length);
    }
}
