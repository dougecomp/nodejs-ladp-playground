import crypto from 'crypto'
import { describe, before, afterEach, it } from 'mocha'
import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { createSandbox, SinonSandbox } from 'sinon'

import testingEnvVars from './env-test'
import { LdapConnection as sut } from '../src/ldap-connection'

chai.use(chaiAsPromised)
const expect = chai.expect

describe('LDAP Server', () => {
  let sandbox: SinonSandbox
  const highPrivilegeUserDN = `cn=${testingEnvVars.user},${testingEnvVars.baseDN}`
  const newUser = 'cn=user99'
  const password = 'secret'
  const salt = 'salt'
  const passwordWithHexEncoding = Buffer.from(salt).toString('hex')

  before(() => {
    sandbox = createSandbox()
  })
  afterEach(() => {
    sandbox.restore()
  })

  describe('Connection', () => {
    it('should not create a connection instance to LDAP server with invalid url', () => {
      expect(() => { sut.connect('invalid_url') }).to.throw()
    })

    it('should create a connection instance to LDAP server with valid url', () => {
      expect(() => { sut.connect('ldap://valid.server.url') }).to.not.throw()
    })
  })

  describe('Authentication', () => {
    it('should not authenticate to LDAP server if connection could not be stablished', async () => {
      const throwException = sandbox.fake.rejects('Could not connect to ldap server')
      sandbox.replace(sut, 'login', throwException)
      sut.connect('ldap://valid.server.url')
      await expect(sut.login('user', 'password')).to.be.rejected
      expect(sut.isLogged()).to.be.equals(false)
    })

    it('should not authenticate on LDAP server with invalid credentials', async () => {
      sut.connect(testingEnvVars.url)
      try {
        await expect(sut.login('invalid_login', 'invalid_password')).to.be.rejected
      } finally {
        await expect(sut.logout()).to.be.fulfilled
        expect(sut.isLogged()).to.be.equals(false)
      }
    })

    it('should authenticate on LDAP server with valid credentials', async () => {
      sut.connect(testingEnvVars.url)
      expect(sut.isLogged()).to.be.equals(false)
      await expect(sut.login(highPrivilegeUserDN, testingEnvVars.password)).to.be.fulfilled
      expect(sut.isLogged()).to.be.equals(true)
      await expect(sut.logout()).to.be.fulfilled
      expect(sut.isLogged()).to.be.equals(false)
    })

    it('should authenticate on LDAP server when there is already a logged user', async () => {
      sut.connect(testingEnvVars.url)
      await expect(sut.login(highPrivilegeUserDN, testingEnvVars.password)).to.be.fulfilled
      expect(sut.isLogged()).to.be.equals(true)
      await sut.addUser(`${newUser},${testingEnvVars.baseDN}`, {
        sn: 'User99',
        userPassword: password
      })
      await expect(sut.login(`${newUser},${testingEnvVars.baseDN}`, password)).to.be.fulfilled
      expect(sut.isLogged()).to.be.equals(true)
      await expect(sut.login(highPrivilegeUserDN, testingEnvVars.password)).to.be.fulfilled
      expect(sut.isLogged()).to.be.equals(true)
      await expect(sut.remove(`${newUser},${testingEnvVars.baseDN}`)).to.be.fulfilled
      await sut.logout()
      expect(sut.isLogged()).to.be.equals(false)
    })

    it('should authenticate and retrieve logged user with raw password', async () => {
      await sut.login(highPrivilegeUserDN, testingEnvVars.password)
      await sut.addUser(`${newUser},${testingEnvVars.baseDN}`, {
        sn: 'User99',
        userPassword: password
      })
      await sut.logout()

      const foundedUser = await sut.searchUser(`${newUser}`, password, testingEnvVars.baseDN, `(${newUser})`)
      expect(foundedUser).to.have.property('dn')
      expect(foundedUser).to.have.property('cn')
      expect(foundedUser.dn).to.be.equals(`${newUser},${testingEnvVars.baseDN}`)
      expect(foundedUser.cn).to.be.equals('user99')
      expect(foundedUser.sn).to.be.equals('User99')
      expect(foundedUser.userPassword).to.be.equals(password)

      await sut.login(highPrivilegeUserDN, testingEnvVars.password)
      await sut.remove(`${newUser},${testingEnvVars.baseDN}`)
      await sut.logout()
    })

    it('should authenticate and retrieve logged user with hashed password using MD5', async () => {
      const hashAlgorithm = 'MD5'
      const md5HashedPasswordWithHexEncoding = crypto.createHash(hashAlgorithm).update(password).digest('hex')
      const Md5HashedPasswordConvertedFromHexToBase64 = Buffer.from(md5HashedPasswordWithHexEncoding, 'hex').toString('base64')

      await sut.login(highPrivilegeUserDN, testingEnvVars.password)
      await sut.addUser(`${newUser},${testingEnvVars.baseDN}`, {
        sn: 'User99',
        userPassword: `{${hashAlgorithm}}${Md5HashedPasswordConvertedFromHexToBase64}`
      })
      await sut.logout()

      try {
        const user = await sut.searchUser(`${newUser}`, password, testingEnvVars.baseDN, `(${newUser})`)
        expect(user.userPassword).to.be.equals(`{${hashAlgorithm}}${Md5HashedPasswordConvertedFromHexToBase64}`)
      } finally {
        await sut.login(highPrivilegeUserDN, testingEnvVars.password)
        await sut.remove(`${newUser},${testingEnvVars.baseDN}`)
        await sut.logout()
      }
    })

    it('should authenticate and retrieve logged user with hashed password using MD5 with salt (SMD5)', async () => {
      const hashAlgorithm = 'MD5'
      const md5HashAndSaltDigestWithHexEncoding = crypto.createHash(hashAlgorithm).update(password.concat(salt)).digest('hex')
      const md5HashAndSaltConvertedFromHexToBase64 = Buffer.from(md5HashAndSaltDigestWithHexEncoding.concat(passwordWithHexEncoding), 'hex').toString('base64')

      await sut.login(highPrivilegeUserDN, testingEnvVars.password)
      await sut.addUser(`${newUser},${testingEnvVars.baseDN}`, {
        sn: 'User99',
        userPassword: `{S${hashAlgorithm}}${md5HashAndSaltConvertedFromHexToBase64}`
      })
      await sut.logout()

      try {
        const user = await sut.searchUser(`${newUser}`, password, testingEnvVars.baseDN, `(${newUser})`)
        expect(user.userPassword).to.be.equals(`{S${hashAlgorithm}}${md5HashAndSaltConvertedFromHexToBase64}`)
      } finally {
        await sut.login(highPrivilegeUserDN, testingEnvVars.password)
        await sut.remove(`${newUser},${testingEnvVars.baseDN}`)
        await sut.logout()
      }
    })

    it('should authenticate and retrieve logged user with hashed password using SHA1 (SHA)', async () => {
      const hashAlgorithm = 'SHA1'
      const sha1HashedPasswordWithHexEncoding = crypto.createHash(hashAlgorithm).update(password).digest('hex')
      const sha1HashedPasswordConvertedFromHexToBase64 = Buffer.from(sha1HashedPasswordWithHexEncoding, 'hex').toString('base64')

      await sut.login(highPrivilegeUserDN, testingEnvVars.password)
      await sut.addUser(`${newUser},${testingEnvVars.baseDN}`, {
        sn: 'User99',
        userPassword: `{SHA}${sha1HashedPasswordConvertedFromHexToBase64}`
      })
      await sut.logout()

      try {
        const user = await sut.searchUser(`${newUser}`, password, testingEnvVars.baseDN, `(${newUser})`)
        expect(user.userPassword).to.be.equals(`{SHA}${sha1HashedPasswordConvertedFromHexToBase64}`)
      } finally {
        await sut.login(highPrivilegeUserDN, testingEnvVars.password)
        await sut.remove(`${newUser},${testingEnvVars.baseDN}`)
        await sut.logout()
      }
    })

    it('should authenticate and retrieve logged user with hashed password using SHA1 with salt (SSHA)', async () => {
      const hashAlgorithm = 'SHA1'
      const sha1HashAndSaltDigestWithHexEncoding = crypto.createHash(hashAlgorithm).update(password.concat(salt)).digest('hex')
      const sha1HashAndSaltConvertedFromHexToBase64 = Buffer.from(sha1HashAndSaltDigestWithHexEncoding.concat(passwordWithHexEncoding), 'hex').toString('base64')

      await sut.login(highPrivilegeUserDN, testingEnvVars.password)
      await sut.addUser(`${newUser},${testingEnvVars.baseDN}`, {
        sn: 'User99',
        userPassword: `{SSHA}${sha1HashAndSaltConvertedFromHexToBase64}`
      })
      await sut.logout()

      try {
        const user = await sut.searchUser(`${newUser}`, password, testingEnvVars.baseDN, `(${newUser})`)
        expect(user.userPassword).to.be.equals(`{SSHA}${sha1HashAndSaltConvertedFromHexToBase64}`)
      } finally {
        await sut.login(highPrivilegeUserDN, testingEnvVars.password)
        await sut.remove(`${newUser},${testingEnvVars.baseDN}`)
        await sut.logout()
      }
    })
  })

  describe('CRUD User', () => {
    it('should not insert user on LDAP server with invalid base DN', async () => {
      sut.connect(testingEnvVars.url)
      await sut.login(highPrivilegeUserDN, testingEnvVars.password)
      await expect(sut.addUser('dc=invalid,dc=dn', {
        cn: 'user99',
        sn: 'User99'
      })).to.be.rejectedWith(Error, 'no global superior knowledge Code: 0x35')
      await sut.logout()
    })

    it('should not insert user on LDAP server with invalid attribute', async () => {
      sut.connect(testingEnvVars.url)
      await sut.login(highPrivilegeUserDN, testingEnvVars.password)
      await expect(sut.addUser(`${testingEnvVars.baseDN}`, {
        invalid_attribute: 'invalid_value'
      })).to.be.rejectedWith(Error, 'invalid_attribute: AttributeDescription contains inappropriate characters Code: 0x11')
      await sut.logout()
    })

    it('should insert, find and remove user on LDAP server', async () => {
      sut.connect(testingEnvVars.url)
      await sut.login(highPrivilegeUserDN, testingEnvVars.password)
      await expect(sut.addUser(`${newUser},${testingEnvVars.baseDN}`, {
        sn: 'User99'
      })).to.be.fulfilled
      const insertedUsers = await expect(sut.search(testingEnvVars.baseDN, `(${newUser})`)).to.be.fulfilled
      expect(insertedUsers).to.have.length(1)
      expect(insertedUsers[0].dn).to.be.equal(`${newUser},${testingEnvVars.baseDN}`)
      await expect(sut.remove(`${newUser},${testingEnvVars.baseDN}`)).to.be.fulfilled
      const users = await expect(sut.search(testingEnvVars.baseDN, `(${newUser})`)).to.be.fulfilled
      expect(users).to.have.length(0)
      await sut.logout()
    })

    it('should update a user attribute')

    it('should reset password')

    it('should change password')
  })

  describe('CRUD Organizational Unit', () => {
    it('should insert, find and remove organizational unity', async () => {
      const orgUnit = 'ou=neworgunity'
      await sut.login(highPrivilegeUserDN, testingEnvVars.password)
      await expect(sut.addOrganizationalUnity(`${orgUnit},${testingEnvVars.baseDN}`)).to.be.fulfilled
      const insertedOrgUnits = await expect(sut.search(testingEnvVars.baseDN, `(${orgUnit})`)).to.be.fulfilled
      expect(insertedOrgUnits).to.have.length(1)
      expect(insertedOrgUnits[0].dn).to.be.equal(`${orgUnit},${testingEnvVars.baseDN}`)
      await expect(sut.remove(`${orgUnit},${testingEnvVars.baseDN}`)).to.be.fulfilled
      const orgUnits = await expect(sut.search(testingEnvVars.baseDN, `(${orgUnit})`)).to.be.fulfilled
      expect(orgUnits).to.have.length(0)
      await sut.logout()
    })

    it('should insert user into a organizational unity', async () => {
      const orgUnit = 'ou=neworgunity'

      await sut.login(highPrivilegeUserDN, testingEnvVars.password)

      await sut.addOrganizationalUnity(`${orgUnit},${testingEnvVars.baseDN}`)

      await expect(sut.addUser(`${newUser},${orgUnit},${testingEnvVars.baseDN}`, {
        sn: 'User99'
      })).to.be.fulfilled
      const insertedUsers = await expect(sut.search(`${orgUnit},${testingEnvVars.baseDN}`, `(${newUser})`)).to.be.fulfilled
      expect(insertedUsers).to.have.length(1)
      expect(insertedUsers[0].dn).to.be.equal(`${newUser},${orgUnit},${testingEnvVars.baseDN}`)

      sut.remove(`${newUser},${orgUnit},${testingEnvVars.baseDN}`)
      const users = await sut.search(`${orgUnit},${testingEnvVars.baseDN}`, `(${newUser})`)
      expect(users).to.have.length(0)

      await sut.remove(`${orgUnit},${testingEnvVars.baseDN}`)
      const orgUnits = await sut.search(testingEnvVars.baseDN, `(${orgUnit})`)
      expect(orgUnits).to.have.length(0)

      await sut.logout()
    })

    it('should not delete organizational unity with entries inside', async () => {
      const orgUnit = 'ou=neworgunity'

      await sut.login(highPrivilegeUserDN, testingEnvVars.password)

      await sut.addOrganizationalUnity(`${orgUnit},${testingEnvVars.baseDN}`)

      await sut.addUser(`${newUser},${orgUnit},${testingEnvVars.baseDN}`, {
        sn: 'User99'
      })

      await expect(sut.remove(`${orgUnit},${testingEnvVars.baseDN}`)).to.be.rejectedWith(Error, 'subordinate objects must be deleted first Code: 0x42')

      sut.remove(`${newUser},${orgUnit},${testingEnvVars.baseDN}`)
      const users = await sut.search(`${orgUnit},${testingEnvVars.baseDN}`, `(${newUser})`)
      expect(users).to.have.length(0)

      await sut.remove(`${orgUnit},${testingEnvVars.baseDN}`)
      const orgUnits = await sut.search(testingEnvVars.baseDN, `(${orgUnit})`)
      expect(orgUnits).to.have.length(0)
      await sut.logout()
    })
  })
})
