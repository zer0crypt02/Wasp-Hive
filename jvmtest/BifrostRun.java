import java.lang.reflect.Field;
import java.lang.reflect.Method;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.BuildersKt;
import kotlinx.coroutines.CoroutineScope;

/**
 * Bifrost 2.1.4'un GERCEK FusClient.makeReq akisini JVM'de calistirir:
 * GenerateNonce -> BinaryInform (Smart endpoint). Boylece transport katmanindaki
 * tum farklar (ktor headers vs) otomatik olarak Bifrost ile ayni olur.
 */
public class BifrostRun {
    static class EmptyCont implements Continuation<Object> {
        public CoroutineContext getContext() { return EmptyCoroutineContext.INSTANCE; }
        public void resumeWith(Object result) {}
    }

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

    static void setField(Object inst, String name, Object val) throws Exception {
        Field f = inst.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(inst, val);
    }

    /** suspend fonksiyonu runBlocking icinde gercek coroutine ile calistirir */
    static Object runSuspend(SuspendCall body) {
        try {
            return BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE,
                    new Function2<CoroutineScope, Continuation<Object>, Object>() {
                        @Override
                        public Object invoke(CoroutineScope scope, Continuation<Object> cont) {
                            try {
                                return body.run(cont);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                    });
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    interface SuspendCall {
        Object run(Continuation<Object> cont) throws Exception;
    }

    /** BinaryInform tek deneme — lambda final-parite icin parametrik yardimci */
    static Object informOnce(final Object fus, final Method makeReq, final Object binInform, final String xml) {
        return runSuspend(cont -> makeReq.invoke(fus, binInform, xml, null, false, cont));
    }

    /** GenerateNonce tek deneme */
    static Object genOnce(final Object fus, final Method makeReq, final Object genNonce) {
        return runSuspend(cont -> makeReq.invoke(fus, genNonce, "", null, true, cont));
    }

    public static void main(String[] args) throws Exception {
        String fw = "A715FXXSBDXB1/A715FOXMBDXB1/A715FXXSBDXB1/A715FXXSBDXB1";
        String model = "SM-A715F";
        String region = "DBT";
        String imei = "350000029442064";

        Class<?> reqEnumCls = Class.forName("tk.zwander.common.tools.FusClient$Request");
        Object genNonce = null, binInform = null;
        for (Object e : reqEnumCls.getEnumConstants()) {
            String n = ((Enum<?>) e).name();
            if (n.equals("GENERATE_NONCE")) genNonce = e;
            if (n.equals("BINARY_INFORM")) binInform = e;
        }
        if (genNonce == null || binInform == null) throw new IllegalStateException("enum bulunamadi");

        Class<?> fusCls = Class.forName("tk.zwander.common.tools.FusClient");
        Object fus = fusCls.getField("INSTANCE").get(null);

        // makeReq imzasini calisma aninda kesfet (2.1.4: (Request,String,String,boolean,Continuation) bekleniyor)
        Method makeReq = null;
        for (Method m : fus.getClass().getDeclaredMethods()) {
            if (m.getName().equals("makeReq") && m.getParameterCount() == 5) {
                makeReq = m;
                m.setAccessible(true);
            }
        }
        if (makeReq == null) throw new IllegalStateException("makeReq bulunamadi");
        System.out.println("makeReq params: " + java.util.Arrays.toString(makeReq.getParameterTypes()));

        // 1) GenerateNonce
        Object resp1 = genOnce(fus, makeReq, genNonce);
        System.out.println("--- GenerateNonce body ---");
        System.out.println(String.valueOf(resp1).substring(0, Math.min(400, String.valueOf(resp1).length())));
        Object nonce = getField(fus, "nonce");
        Object auth = getField(fus, "auth");
        System.out.println("nonce = " + nonce);
        System.out.println("auth  = " + auth);

        // 2) BinaryInform XML (2.1.4 createBinaryInform — 6 param, continuation yok)
        Class<?> reqCls = Class.forName("tk.zwander.common.tools.Request");
        Object req = reqCls.getField("INSTANCE").get(null);
        Class<?>[] cbiTypes = {String.class, String.class, String.class, String.class, String.class, boolean.class};
        String xml = (String) call(req, "createBinaryInform", cbiTypes,
                new Object[]{fw, model, region, nonce, imei, false});
        System.out.println("--- BinaryInform XML (Bifrost 2.1.4 uretimi, byte-for-byte) ---");
        System.out.println(xml);

        // 3) BinaryInform — 401 olursa nonce yenile + retry (Bifrost paritesi)
        for (int attempt = 1; attempt <= 3; attempt++) {
            Object resp2 = informOnce(fus, makeReq, binInform, xml);
            String body = String.valueOf(resp2);
            System.out.println("--- BinaryInform deneme " + attempt + " ---");
            System.out.println(body.length() > 2500 ? body.substring(0, 2500) : body);
            if (body.contains("BINARY_NAME") || !body.contains(">401<")) {
                System.out.println("SONUC: BinaryInform " + (body.contains("BINARY_NAME") ? "BASARILI ✔" : "bitti"));
                break;
            }
            // 401 -> yeni nonce
            genOnce(fus, makeReq, genNonce);
            nonce = getField(fus, "nonce");
            auth = getField(fus, "auth");
            System.out.println("yeni nonce = " + nonce + " auth = " + auth);
            xml = (String) call(req, "createBinaryInform", cbiTypes,
                    new Object[]{fw, model, region, nonce, imei, false});
        }
    }
}
