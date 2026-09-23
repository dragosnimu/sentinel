/**
 * GENERAT — nu edita manual.
 *
 * Regenerează cu `npm run generate-migrations-manifest`, din `aggregator/`,
 * după orice migrație nouă sau editată în `migrations/`. Vezi capul lui
 * `bin/generate-migrations-manifest.ts` pentru de ce fișierul ăsta există, și
 * `tests/migrations-manifest.test.ts` pentru proba care pică dacă fișierul ăsta
 * se desincronizează de `migrations/`.
 */

export type ManifestStatement = { readonly index: number; readonly sha256: string };
export type ManifestMigration = {
  readonly file: string;
  readonly statements: readonly ManifestStatement[];
};

export const MIGRATIONS_MANIFEST: readonly ManifestMigration[] = [
  { file: "0001_core.sql", statements: [
    { index: 1, sha256: "2b27d174d34281b9f9c370361992690bf1fff9fbcdd65298e4be2d53c406ae88" },
    { index: 2, sha256: "a654469608f3dde5d52dec927e56b1857df7ec6215813a318d06fcbdb8c1fddc" },
    { index: 3, sha256: "c87d17312ced9f87f4e624be9fcced9f24d5a0e37755c0b24a6d064213b94fb3" },
    { index: 4, sha256: "67f7c5f025f1d4fd382a04fc1f7c9a7811fba066c07ef3c2c1dc79e572451bc4" },
    { index: 5, sha256: "8d793d9e10c794b54adf8b6f20bcd7b62ea8bd08e8fbec7aca235d25a5d7a2c8" },
    { index: 6, sha256: "dab7e5733ed34d290911bdb0475f52b574fe4b342ae5fd576eed578d38cd272c" },
  ] },
  { file: "0002_chain.sql", statements: [
    { index: 1, sha256: "644f965dfd6aaa52de552e212b4a451c306e33227344a446c3a2b7551e607157" },
  ] },
  { file: "0003_entities.sql", statements: [
    { index: 1, sha256: "2f04154731c1122ffa2b7c5580f11e650de4bc75ea60bca7fdc9baaa5da5c715" },
    { index: 2, sha256: "6eb6e9580ee983cf66f17af0f91353543a8a5e7d63cdbbd3df178e109ce32ec0" },
    { index: 3, sha256: "bb145e134edfea4af9d0624cb1f8186f1b7a7a6bbb5c7683687d9587304b7be1" },
    { index: 4, sha256: "4d6be3b5c8a84385027b97eb85d43ff3e1aef27a2904741fa8c7ca5ec8045eab" },
    { index: 5, sha256: "5072864b91b01802e3d02f04be4a970e49f2c765bc56b5e1b1ac32470cccdad6" },
    { index: 6, sha256: "5ee9879e4f148365a7c18636703814ce0e6c71c541550d9da6e66395a4565227" },
    { index: 7, sha256: "a6e6f701898b1c6e2f2832dc8f094b3812556f9f81c2399f91197c8248786295" },
    { index: 8, sha256: "e2ca8ef201d07ebf1bced8d24f1a8480e908b670f25c7122348b983d6ec8d07d" },
    { index: 9, sha256: "a45fe08abd403885b98c5941ed9d5812db8831a3b55cb5168f7971166da8c27d" },
    { index: 10, sha256: "65224894e47d98bdde9dee5c450d00861f43515a6da83985a686dda5e75e37db" },
    { index: 11, sha256: "949a662f93fa6c01d8d6e31adcf216fb4cce24f5b6e5f04df06b0318e46f95cb" },
    { index: 12, sha256: "de3ba4e5cbe372962a4b885ef00025d28eca15cc7580107d3fee8e3befe00d82" },
    { index: 13, sha256: "31d48935cffb9b4c61875fb999972af708c169e12613939824a1ea0c7ceeb889" },
    { index: 14, sha256: "85f88c6cb0210011cbaf28c7f1b5499c4c501f16524ac4cd8e30ff997296a864" },
    { index: 15, sha256: "d43cdb48db6c5d1c63fe4c0197e29f9ecdd3f9164e8f7bdac21127592086a759" },
    { index: 16, sha256: "bad60903c2e3df6f39ef64b4753463d3b7e623014385f04af4b952b9b31b8039" },
    { index: 17, sha256: "1e8c3c21750054dcdcc11d3abd6010a0ab02aadd1d65c681f21c6514e9610417" },
    { index: 18, sha256: "20584bcd694e8e41c999bd91b6fd58216561d3a188752035a52c3d1680190a94" },
  ] },
  { file: "0004_health.sql", statements: [
    { index: 1, sha256: "1247115bb1cc5062e5f3021d4a55c31d5f305a7002afdbb1b3b63712f804161f" },
    { index: 2, sha256: "f24433a27a0e92988f4b504d389c6a6cfb116bf26041bc1191c0e9e3bf858dd9" },
    { index: 3, sha256: "09f4360eb748b4c4eb1ec84594067ed1940185919cd05d9bec93ce21960497d2" },
    { index: 4, sha256: "e3aa2993287f8eab1d5e5c2aa5b45c6b027a92935044f7e88d963a1a806d932d" },
    { index: 5, sha256: "1374976a1152b95ccfb1f95f289a1af11f669c1e7dde0ba8919497a110473dd8" },
    { index: 6, sha256: "52e432b1f95cf298a7d92d1a4b24bb342d8674084f0cab11bd37d2a142ecfc4d" },
    { index: 7, sha256: "a7c7e287f8ec9d21f1253591d7e668c12897c586a120f2749e79016a82ebf47e" },
    { index: 8, sha256: "8dacbd6a321357146fdaf9e0867bfde2f5b8d511f4c51033d90f8524e0ad421b" },
    { index: 9, sha256: "a32137fe3b524b1996fa599eab805eb9003b509c4b755923a2b9d2c7e46b55e5" },
  ] },
  { file: "0005_patch.sql", statements: [
    { index: 1, sha256: "075c4adc4cb571616b445cb047b29e98d9af02eb3e2b6eee0708ed55d3d7801d" },
    { index: 2, sha256: "05068f3959dc1109657ec275a42277a316823b02c9d64c094f51887c04b05308" },
    { index: 3, sha256: "d91a41832daebe44ca1d4f5525f992815105c87a40d5945df5462b29026ccead" },
    { index: 4, sha256: "6aa4bd4fe84b3f5fe1bb2cacd66497c27721e25f5e9ebc20392f4d123d0e1183" },
    { index: 5, sha256: "cb220afbdeb6a3c8415325b26c2fa95350ce3ac5248692d4ce2def65fea0cc9c" },
    { index: 6, sha256: "8a5688c03fc1b9f1a1515554babe2da0256636f44dcdc28f013fbe0e69954756" },
    { index: 7, sha256: "efdc5201a4eb290893c7d795782f01bd22af58279a4b2242376a200210d910a8" },
    { index: 8, sha256: "20b8bc4ec875e04e009b3706f8aa954d9495240ab6e04b3cc312e3dfee7f59a5" },
    { index: 9, sha256: "b61caa1e8f497cb7f11c2810726a60dfd94e41c84f580c563bf988778dde7d82" },
    { index: 10, sha256: "23ee2bedaee9559fb8ef122487ca3a99122db036d38a5599988179dcc37c822b" },
    { index: 11, sha256: "eac10c3d6845de4a5166200b3943e5c7c83eff8717c25f9a8d51d0f535a7d265" },
    { index: 12, sha256: "c273c54303372a6a3ad29071f0e0a70c5d17d5b709ed3d92b810a0665f95f8f9" },
    { index: 13, sha256: "72ff16a117bf51404721e6ea3d4425ad9ed38091c13d398412e19a4638ed42a6" },
  ] },
  { file: "0006_incident_updated_at.sql", statements: [
    { index: 1, sha256: "7f7661e631ef75f354ebc83b966f66650be19ec5246ceb957f8596ea46e12a03" },
    { index: 2, sha256: "9d909eff40722b14c3a593b43c577c277a65762e5551a754b1544f5512b6723e" },
  ] },
  { file: "0007_incident_auto_action.sql", statements: [
    { index: 1, sha256: "209265cab4abb2cf2df11cc5df90392428333d0a50e51fc9b048aa5da49f2454" },
    { index: 2, sha256: "2bcb64d693cb5cf14f88628bf0c38e55a608c37fe763715c261aa1fc003e8d04" },
  ] },
  { file: "0008_auth.sql", statements: [
    { index: 1, sha256: "8aa69c380f62878b6d13e3430bc60b58a090df8127628740372455ad8af3b164" },
    { index: 2, sha256: "dfb8f2ee66538ae4cdc1b987c480bf8d6cd00ee522bd66bbc643ba2fa5cf4674" },
    { index: 3, sha256: "d89fd76378a033950c8d91ba85db06d05bb11387a1126ac5812861ec93428c7e" },
    { index: 4, sha256: "2aa3402fba38b9831fcbe36bff742524c36481bcd5d2132aa908d8bc25caf8e4" },
    { index: 5, sha256: "a00190ffd47b1f3273d0f7c709eee853c34b2bb2d4b16b26be2bb1ae9eb88bbb" },
    { index: 6, sha256: "77c7089d239dbb2eaf8d6f2354dab989f9e80c7cdac4829668acb2cc64e5d909" },
  ] },
  { file: "0009_auth_bounds.sql", statements: [
    { index: 1, sha256: "7e1cd586c27bdd49bbb74906e1ac8db47c51e4e71b07492e86cf4447a7b397ba" },
    { index: 2, sha256: "26bd21b2a43ca46a0d652b3907b1ece6abfb014ff5a39ee60b1608ac8b55e7af" },
    { index: 3, sha256: "d6879f7d28f4a7eec2a3480ddd0eca3901566af9ea5dcc3a11d1ed22c52a0e44" },
    { index: 4, sha256: "bf2ad4ac477cb1bc6ee6c89ca54a43c24bfd9a8ea37d3ae61e78793841350b4d" },
    { index: 5, sha256: "21c70b591c0efc166e667029395819c74a2abb1cc89b6d9af44d556c685db4bf" },
  ] },
  { file: "0010_mutable_updated_at.sql", statements: [
    { index: 1, sha256: "5aa46f33450a6c57357ba6acc387e2f9a191d08f11c4b4635f69ca7a2b286bd1" },
    { index: 2, sha256: "6c6c278afc937c6b1784b6d1a13f879c5b0e4f2c97f1cc885c875e0498e8882c" },
    { index: 3, sha256: "9e69ada771dbb11f08829ed4235a74775255603651e83edc67d193ef90f2d61a" },
    { index: 4, sha256: "eaa0a04913c1db1aff2013c0a94c953b08d6b69f9c34af30cf27a856181d62f1" },
    { index: 5, sha256: "eda28c507137bb7ce777a49e0a63bc0fe19dc6ea9952adf26b360fdcad746267" },
    { index: 6, sha256: "8b41b5ab54fb70251074a688168a298483f3ab0b63358fcd7a41520375a377dd" },
  ] },
  { file: "0011_text_watermark.sql", statements: [
    { index: 1, sha256: "23ce355b87c19e5c92fac4b3c901a3bfba94c1f45dc7bc41cda33edb38879cd6" },
  ] },
  { file: "0012_selfcheck_updated_at.sql", statements: [
    { index: 1, sha256: "5f619a571f51192078dc595487c8239b4559de05388eb365ad09ba1c302a3118" },
    { index: 2, sha256: "e6da780d75c8bf623fcd242d6027171aefb52bac0ba2d02f999ccf2f89ebe7b9" },
  ] },
  { file: "0013_scans_updated_at.sql", statements: [
    { index: 1, sha256: "984867c15b8030c9366d811b89cde15ab7eaed902fbf541d6bcdcc41a54e26df" },
    { index: 2, sha256: "3a410398bb72585da065a61080b40be3c0b5d5c1ea5afd3a472badcbe34cb594" },
  ] },
  { file: "0014_rollup_updated_at.sql", statements: [
    { index: 1, sha256: "ce5924d1c95ff9d4ea5663dc9d69c79a905790ea0f2496612f2fd104666c691a" },
    { index: 2, sha256: "201d9f5d99f0a8ef430428232de672d667a57de84fe68f7e5121f35b86f64224" },
  ] },
  { file: "0015_login_history.sql", statements: [
    { index: 1, sha256: "4f800678fe498d389542e3094913ef98b20873799ada79283b9965a678348487" },
    { index: 2, sha256: "f1112076ff88fb025961d6644af29bb84f59198801a2435f0bbeb7157e59eca0" },
  ] },
  { file: "0016_commands_purged.sql", statements: [
    { index: 1, sha256: "830dcb3026d06738032974030a2aee396eb1d197b6a166e81ac772ef782105c2" },
  ] },
];
