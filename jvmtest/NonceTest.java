import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;

/**
 * Bifrost'un CryptUtils.decryptNonce (suspend) fonksiyonunu JVM'den cagirir.
 * Fonksiyon icerisinde suspension noktasi yok (saf CPU + blocking IO), bu yuzden
 * bos bir Continuation ile cagirildiginda sonuc direkt doner (COROUTINE_SUSPENDED degil).
 */
public class NonceTest {
    static class EmptyCont implements Continuation<Object> {
        @Override
        public CoroutineContext getContext() {
            return EmptyCoroutineContext.INSTANCE;
        }
        @Override
        public void resumeWith(Object result) {
            // hicbir zaman cagrilmayacak (suspension yok)
        }
    }

    public static void main(String[] args) throws Exception {
        Class<?> cls = Class.forName("tk.zwander.common.tools.CryptUtils");
        Object inst = cls.getField("INSTANCE").get(null);
        Continuation<Object> cont = new EmptyCont();

        for (String nonce : args) {
            // decryptNonce(input: String, continuation): String
            var m = cls.getMethod("decryptNonce", String.class, Continuation.class);
            Object res = m.invoke(inst, nonce, cont);
            System.out.println("decryptNonce(" + nonce + ") = " + res);

            //.authenticateBlock birebir karsilastirma icin ham 16 byte da alinabilir:
            // (gerekirse eklenir)
        }
    }
}
