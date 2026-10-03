package com.deceipt.native.protocol

/** Loads the frozen vector fixtures copied into `src/test/resources/vectors`. */
object VectorFixtures {

    fun load(name: String): Map<String, Any?> {
        val stream = VectorFixtures::class.java.classLoader!!.getResourceAsStream("vectors/$name")
            ?: error("missing test resource vectors/$name")
        val text = stream.bufferedReader(Charsets.UTF_8).readText()
        return TestJson.obj(TestJson.parse(text))
    }

    fun loadFixture(name: String): Map<String, Any?> {
        val stream = VectorFixtures::class.java.classLoader!!.getResourceAsStream("fixtures/$name")
            ?: error("missing test resource fixtures/$name")
        val text = stream.bufferedReader(Charsets.UTF_8).readText()
        return TestJson.obj(TestJson.parse(text))
    }

    fun cases(file: String): List<Map<String, Any?>> =
        TestJson.arr(load(file)["cases"]).map { TestJson.obj(it) }

    /** A named key from handshake-valid.json's `keys` block. */
    fun okmSlice(handshakeValid: Map<String, Any?>, name: String): ByteArray {
        val keys = TestJson.obj(handshakeValid["keys"])
        return Bytes.fromHex(TestJson.str(keys[name]))
    }

    /** Anchors parsed from credentials.json's per-case `anchors_hex` map. */
    fun anchorsFrom(case: Map<String, Any?>): List<Credential.Anchor> {
        val m = TestJson.obj(case["anchors_hex"])
        return m.map { (idHex, pubHex) ->
            Credential.Anchor(Bytes.fromHex(idHex), Bytes.fromHex(TestJson.str(pubHex)), null)
        }
    }

    /** The test device seed for the pre-provisioned merchant (`merchant-test-1`). */
    fun testKey(name: String): Pair<ByteArray, ByteArray> {
        val keys = TestJson.arr(load("keys/test-keys.json")["keys"])
        val k = TestJson.obj(keys.first { TestJson.str(TestJson.obj(it)["name"]) == name })
        val privateHex = TestJson.str(k["private_seed_hex"] ?: k["private_scalar_hex"])
        return Pair(Bytes.fromHex(privateHex), Bytes.fromHex(TestJson.str(k["public_key_hex"])))
    }

    fun pinnedAnchors(): List<Credential.Anchor> {
        val anchors = TestJson.arr(loadFixture("trust-anchors-v1.json")["anchors"])
        return anchors.map {
            val a = TestJson.obj(it)
            Credential.Anchor(Bytes.fromHex(TestJson.str(a["anchor_id_hex"])), Bytes.fromHex(TestJson.str(a["public_key_hex"])), a["label"] as? String)
        }
    }
}
