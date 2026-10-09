import java.lang.reflect.Field;
import java.lang.reflect.Method;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;

/**
 * Bifrost'un KENDI fonksiyonlarini cagirip urettigi exact XML + Authorization
 * string'lerini uretir — benim Python portumun ciktilariyla bayt-bayt karsilastirma icin.
 */
public class BifrostDiff {
    static class EmptyCont implements Continuation<Object> {
        @Override
        public CoroutineContext getContext() { return EmptyCoroutineContext.INSTANCE; }
        @Override
        public void resumeWith(Object result) {}
    }

    static Object call(Object obj, String name, Class<?>[] types, Object[] args) throws Exception {
        Method m;
        try {
            m = obj.getClass().getMethod(name, types);
        } catch (NoSuchMethodException e) {
            // private suspend fun'lar icin declared + setAccessible
            m = obj.getClass().getDeclaredMethod(name, types);
            m.setAccessible(true);
        }
        return m.invoke(obj, args);
    }

    static void setObjectField(Object inst, String name, Object val) throws Exception {
        Field f = inst.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(inst, val);
    }

    public static void main(String[] args) throws Exception {
        Continuation<Object> cont = new EmptyCont();
        Class<?> contCls = Continuation.class;

        String fw = "A715FXXSBDXB1/A715FOXMBDXB1/A715FXXSBDXB1/A715FXXSBDXB1";
        String model = "SM-A715F";
        String region = "DBT";
        String imei = "350000029442064";

        Class<?> reqCls = Class.forName("tk.zwander.common.tools.Request");
        Object req = reqCls.getField("INSTANCE").get(null);

        // ---- Request.createBinaryInform(fw, model, region, nonce, imeiSerial, legacy) ----
        Class<?>[] cbiTypes = {String.class, String.class, String.class, String.class,
                               String.class, boolean.class, contCls};
        Object[] cbiArgs = {fw, model, region, "d7vwky4yh53rvep3", imei, false, cont};
        Object xmlSmart = call(req, "createBinaryInform", cbiTypes, cbiArgs);
        System.out.println("=== SMART XML (Bifrost uretimi) ===");
        System.out.println(xmlSmart);
        System.out.println();

        Object[] cbiArgsL = {fw, model, region, "RsfgFdnhq14UloCf", imei, true, cont};
        Object xmlLegacy = call(req, "createBinaryInform", cbiTypes, cbiArgsL);
        System.out.println("=== LEGACY XML (Bifrost uretimi) ===");
        System.out.println(xmlLegacy);
        System.out.println();

        // ---- Request.getLogicCheck ----
        Object lc = call(req, "getLogicCheck",
                new Class<?>[]{String.class, String.class},
                new Object[]{fw, "d7vwky4yh53rvep3"});
        System.out.println("=== SMART LOGIC_CHECK ===");
        System.out.println(lc);
        System.out.println();

        Object lcL = call(req, "getLogicCheck",
                new Class<?>[]{String.class, String.class},
                new Object[]{fw, "RsfgFdnhq14UloCf"});
        System.out.println("=== LEGACY LOGIC_CHECK ===");
        System.out.println(lcL);
        System.out.println();

        // ---- FusClient.getAuthV (private nonce/auth alanlarini enjekte et) ----
        Class<?> fusCls = Class.forName("tk.zwander.common.tools.FusClient");
        Object fus = fusCls.getField("INSTANCE").get(null);
        setObjectField(fus, "nonce", "d7vwky4yh53rvep3");
        setObjectField(fus, "auth", "bbe2b9c2bbae744179bd18ef2f18317f");
        Class<?>[] gavTypes = {boolean.class, String.class, boolean.class, contCls};
        for (boolean incl : new boolean[]{false, true}) {
            Object authv = call(fus, "getAuthV", gavTypes, new Object[]{incl, null, false, cont});
            System.out.println("=== SMART getAuthV(includeNonce=" + incl + ") ===");
            System.out.println(authv);
            System.out.println();
        }

        // ---- FusClientLegacy.getAuthV (USE_MODERN_AUTH=true yolu) ----
        Class<?> legCls = Class.forName("tk.zwander.common.tools.FusClientLegacy");
        Object leg = legCls.getField("INSTANCE").get(null);
        setObjectField(leg, "nonce", "RsfgFdnhq14UloCf");
        setObjectField(leg, "auth", "753e2b60386603f650194b0591e7297c");
        for (boolean incl : new boolean[]{false, true}) {
            Object authv = call(leg, "getAuthV", gavTypes, new Object[]{incl, null, false, cont});
            System.out.println("=== LEGACY getAuthV(includeNonce=" + incl + ") ===");
            System.out.println(authv);
            System.out.println();
        }
    }
}
