import 'dotenv-safe/config'

export default {
  mainLdap: {
    host: process.env.MAIN_LDAP_HOST!,
    port: process.env.MAIN_LDAP_PORT!,
    user: process.env.MAIN_LDAP_USER!,
    password: process.env.MAIN_LDAP_PASSWORD!,
    baseDN: process.env.MAIN_LDAP_BASE_DN!
  },
  rnpLdap: {
    host: process.env.RNP_LDAP_HOST!,
    port: process.env.RNP_LDAP_PORT!,
    user: process.env.RNP_LDAP_USER!,
    password: process.env.RNP_LDAP_PASSWORD!,
    baseDN: process.env.MAIN_LDAP_BASE_DN!
  }
}
