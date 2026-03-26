package com.desktop.pdfhandler

import android.app.Activity
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider

@InvokeArg
class SignPdfCmsArgs {
    lateinit var tbsBase64: String
    var promptTitle: String? = null
    var promptSubtitle: String? = null
    var promptDescription: String? = null
    var negativeButtonText: String? = null
}

@TauriPlugin
class PdfBiometricSignerPlugin(private val activity: Activity) : Plugin(activity) {

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "pdf_sign_key"
        private const val BC = "BC"
    }

    override fun load(webView: android.webkit.WebView) {
        if (Security.getProvider(BC) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        ensureKeyExists()
    }

    @Command
    fun ensureKey(invoke: Invoke) {
        try {
            ensureKeyExists()

            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val cert = ks.getCertificate(KEY_ALIAS) as X509Certificate

            val ret = JSObject()
            ret.put("alias", KEY_ALIAS)
            ret.put("certDerBase64", b64(cert.encoded))
            invoke.resolve(ret)
        } catch (e: Exception) {
            invoke.reject("ensureKey failed: ${e.message}")
        }
    }

    @Command
    fun signPdfCms(invoke: Invoke) {
        try {
            ensureKeyExists()

            val args = invoke.parseArgs(SignPdfCmsArgs::class.java)
            val tbs = Base64.decode(args.tbsBase64, Base64.NO_WRAP)

            val canAuth = BiometricManager.from(activity).canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG
            )

            if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
                invoke.reject("Biometric strong auth unavailable: code=$canAuth")
                return
            }

            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val privateKey = ks.getKey(KEY_ALIAS, null) ?: run {
                invoke.reject("Private key not found in Android Keystore")
                return
            }
            val cert = ks.getCertificate(KEY_ALIAS) as X509Certificate

            val androidSig = Signature.getInstance("SHA256withECDSA")
            androidSig.initSign(privateKey as java.security.PrivateKey)

            val cryptoObject = BiometricPrompt.CryptoObject(androidSig)
            val executor = ContextCompat.getMainExecutor(activity)
            val fragmentActivity = activity as? FragmentActivity
                ?: throw IllegalStateException("Activity must be FragmentActivity")

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(args.promptTitle ?: "Potwierdź podpis PDF")
                .setSubtitle(args.promptSubtitle ?: "Użyj odcisku palca, aby podpisać dokument")
                .setDescription(args.promptDescription ?: "Klucz prywatny pozostaje w Android Keystore")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText(args.negativeButtonText ?: "Anuluj")
                .build()

            val prompt = BiometricPrompt(
                fragmentActivity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        try {
                            val unlockedSignature = result.cryptoObject?.signature
                                ?: throw IllegalStateException("No Signature in CryptoObject")

                            val cmsDer = buildDetachedCms(unlockedSignature, cert, tbs)

                            val ret = JSObject()
                            ret.put("cmsDerBase64", b64(cmsDer))
                            ret.put("certDerBase64", b64(cert.encoded))
                            invoke.resolve(ret)
                        } catch (e: Exception) {
                            invoke.reject("Signing failed: ${e.message}")
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        invoke.reject("Authentication error [$errorCode]: $errString")
                    }

                    override fun onAuthenticationFailed() {
                        // samo "failed" nie kończy promptu; system pozwala spróbować jeszcze raz
                    }
                }
            )

            prompt.authenticate(promptInfo, cryptoObject)
        } catch (e: Exception) {
            invoke.reject("signPdfCms failed: ${e.message}")
        }
    }

    private fun ensureKeyExists() {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (ks.containsAlias(KEY_ALIAS)) return

        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            KEYSTORE
        )

        val now = Date()
        val until = Date(now.time + 10L * 365 * 24 * 60 * 60 * 1000)

        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setCertificateSubject(X500Principal("CN=Android PDF Signer"))
            .setCertificateSerialNumber(BigInteger.ONE)
            .setCertificateNotBefore(now)
            .setCertificateNotAfter(until)
            .build()

        kpg.initialize(spec)
        kpg.generateKeyPair()
    }

    private fun buildDetachedCms(
        unlockedSignature: Signature,
        certificate: X509Certificate,
        tbs: ByteArray
    ): ByteArray {
        val certStore = JcaCertStore(listOf(certificate))
        val generator = CMSSignedDataGenerator()

        val digestProvider = JcaDigestCalculatorProviderBuilder()
            .setProvider(BC)
            .build()

        val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(digestProvider)
            .build(AndroidKeystoreContentSigner(unlockedSignature), certificate)

        generator.addSignerInfoGenerator(signerInfoGenerator)
        generator.addCertificates(certStore)

        val cms = generator.generate(CMSProcessableByteArray(tbs), false)
        return cms.encoded
    }

    private fun b64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)

    private class AndroidKeystoreContentSigner(
        private val signature: Signature
    ) : ContentSigner {
        private val buffer = ByteArrayOutputStream()

        override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
            return DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA")
        }

        override fun getOutputStream(): OutputStream = buffer

        override fun getSignature(): ByteArray {
            val bytesToSign = buffer.toByteArray()
            signature.update(bytesToSign)
            return signature.sign()
        }
    }
}