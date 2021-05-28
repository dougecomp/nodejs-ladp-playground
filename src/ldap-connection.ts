import { Client } from 'ldapts'

export const LdapConnection = {
  client: null as unknown as Client,

  connect (url: string) {
    this.client = new Client({
      url

    })
  },

  async login (user: string, password: string) {
    await this.client.bind(user, password)
  },

  async logout () {
    await this.client.unbind()
  },

  isLogged () {
    return this.client.isConnected
  },

  async add (baseDn: string, attributes: any) {
    await this.client.add(baseDn, attributes)
  },

  async addUser (baseDn: string, attributes: any) {
    const objectClass = ['inetOrgPerson']
    if (attributes.objectClass) {
      objectClass.concat(objectClass)
    }
    await this.client.add(baseDn, {
      ...attributes,
      objectClass
    })
  },

  async addOrganizationalUnity (baseDn: string) {
    await this.add(baseDn, {
      objectClass: ['organizationalUnit']
    })
  },

  async remove (baseDn: string) {
    await this.client.del(baseDn)
  },

  async search (baseDn: string, filter?: string) {
    return (await this.client.search(baseDn, {
      filter
    })).searchEntries
  },

  async searchUser (user: string, password: string, baseDn: string, filter?: string) {
    await this.client.bind(`${user},${baseDn}`, password)
    const results = (await this.client.search(baseDn, {
      filter
    })).searchEntries
    await this.logout()
    return results[0]
  }

}
