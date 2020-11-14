/* eslint-disable no-async-promise-executor */

// Documentation: https://ubntwiki.com/products/software/unifi-controller/api

'use strict'

const axios = require('axios')
const EventEmitter = require('events').EventEmitter
const https = require('https')
const WebSocketClient = require('ws')
const logger = require('winston')

// Add a transport as fall back when no parent logger has been initialized
// to prevent the error: "Attempt to write logs with no transports"
logger.add(new logger.transports.Console({
  level: 'none'
}))

module.exports = class extends EventEmitter {
  constructor (options = {}) {
    super()

    this.baseURL = options.baseURL
    this.user = options.user
    this.password = options.password
    this.site = options.site || 'default'

    this.rejectUnauthorized = options.rejectUnauthorized

    this._session = null
    this._csrfToken = null

    this._wss = null
  }

  /**
   * Internal method to call the specified endpoint of the controller.
   * @param {Object} [options] - The options for the API call.
   * @param {string} options.method - The http method to use.
   * @param {string} options.path - The endpoint to use (will be prefixed by /api).
   * @param {string} [body] - The payload when using POST, PUT, PATCH or DELETE as method.
   */
  _apiRequest (options = {}, body = '') {
    var self = this

    return new Promise((resolve, reject) => {
      const headers = {
        'Content-Type': 'application/json',
        Accept: 'application/json'
      }

      if (self._session) {
        headers.cookie = `unifises=${self._session};`
        headers['x-csrf-token'] = self._csrfToken
      }

      options.httpsAgent = new https.Agent({
        rejectUnauthorized: self.rejectUnauthorized
      })
      options.method = options.method || 'GET'
      options.baseURL = `${self.baseURL}/api`
      options.url = options.path || '/'
      options.data = body

      options.headers = headers

      logger.silly(`UnifiController._apirequest: Entering with ${JSON.stringify(options)}`)

      axios(options)
        .then(response => {
          // Return the response data
          return resolve({
            data: response.data,
            headers: response.headers
          })
        })
        .catch(async error => {
          if (error.code === 'DEPTH_ZERO_SELF_SIGNED_CERT') {
            logger.error('SELF SIGNED')
            return reject(new Error('Self signed certificate'))
          }

          // When a non authenticated error is returned, try authenticating when no authentication was in progress
          if (!self._authenticationInProgress && error.response.status === 401) {
            try {
              await self._authenticate()
            } catch (error) {
              return reject(error)
            }

            self._apiRequest(options, body)
              .then(response => {
                return resolve(response)
              })
              .catch(error => {
                return reject(error)
              })
          } else {
            return reject(error)
          }
        })
    })
  }

  /**
   * Internal method to authenticate and obtain a session cookie
   */
  _authenticate () {
    var self = this

    logger.silly('UnifiController._authenticate: Entering...')

    return new Promise((resolve, reject) => {
      self._authenticationInProgress = true

      self._apiRequest({ method: 'POST', path: '/login' }, JSON.stringify({
        username: self.user,
        password: self.password,
        remember: true
      }))
        .then(response => {
          self._authenticationInProgress = false

          if (response.headers['set-cookie']) {
            response.headers['set-cookie'].forEach(cookie => {
              const attrs = cookie.split(';')
              attrs.forEach(attr => {
                switch (true) {
                  case /^unifises=/.test(attr):
                    [, self._session] = attr.match(/^unifises=(.*)/)
                    logger.debug(`Unifi.controller: Received session cookie: ${self._session}`)
                    break

                  case /^csrf_token=/.test(attr):
                    [, self._csrfToken] = attr.match(/^csrf_token=(.*)/)
                    logger.debug(`Unifi.controller: Received csrf token: ${self._csrfToken}`)
                    break
                }
              })
            })
          }

          resolve()
        })
        .catch(error => {
          logger.error(`Unifi.controller: Failed to authenticate - ${error.message}`)

          self._authenticationInProgress = false

          reject(error)
        })
    })
  }

  /**
   * Get alarms
   * @param {object} [options] - Filter options.
   * @param {number} [options.start] - First alarm to return, default is 0.
   * @param {number} [options.limit] - Number of alarms to return, default is 100.
   * @param {number} [options.archived] - Whether or not to return archived alarms, default is false.
   * @param {string} [site] - The site for which return the alarms, default is 'default'
   * @return {object[]} Each alarm is represented by an object containing all relevant properties.
   */
  getAlarms (options = {}, site = 'default') {
    var self = this

    logger.silly('UnifiController.getAlarms: Entering')

    return new Promise((resolve, reject) => {
      if (typeof options === 'string') {
        site = options
        options = {}
      }

      const filter = {
        _start: options.start > 0 ? options.start : 0,
        _limit: options.limit > 0 ? options.limit : 100,
        archived: options.archived || false
      }

      self._apiRequest({ method: 'POST', path: `/s/${site}/stat/alarm` }, filter)
        .then(response => {
          resolve(response.data.data)
        })
        .catch(error => {
          reject(error)
        })
    })
  }

  /**
   * Get a list of connected clients.
   * @param {(string|string[])} [macs] - A single mac address or a list of multiple mac address to filter on.
   * @param {string} [site="default"] - The site for which the list of connected clients must be retrieved, default is 'default'.
   * @return {object[]} clients - An array of objects. Each client is represented by an object with all its properties.
   */
  getClients (macs = [], site = 'default') {
    var self = this

    logger.silly('UnifiController.getClients: Entering')

    return new Promise((resolve, reject) => {
      if (typeof macs === 'string') {
        macs = [macs]
      }

      if (!Array.isArray(macs)) {
        return reject(new Error('Filter must be a single mac address or an array of multiple mac addresses'))
      }

      // Check list of valid mac addresses
      for (let i = 0; i < macs.length; i++) {
        if (!macs[i].match(/([0-9A-Fa-f]{2}[:-]){5}/)) {
          return reject(new Error('Invalid mac address specified'))
        }
      }

      self._apiRequest({ method: 'POST', path: `/s/${site}/stat/sta` }, JSON.stringify({ macs }))
        .then(response => {
          resolve(response.data.data)
        })
        .catch(error => {
          reject(error)
        })
    })
  }

  /**
   * Get a list of all devices for a site.
   * @param {(string|string[])} [macs] - A single mac address or a list of multiple mac address to filter on.
   * @param {string} [site="default"] - The site for which the list of devices must be retrieved, default is 'default'.
   * @return {object[]} devices - An array of objects. Each device is represented by an object with all its properties.
   */
  getDevices (macs = [], site = 'default') {
    var self = this

    logger.silly('UnifiController.getDevices: Entering')

    return new Promise((resolve, reject) => {
      if (typeof macs === 'string') {
        macs = [macs]
      }

      if (!Array.isArray(macs)) {
        return reject(new Error('Filter must be a single mac address or an array of multiple mac addresses'))
      }

      // Check list of valid mac addresses
      for (let i = 0; i < macs.length; i++) {
        if (!macs[i].match(/([0-9A-Fa-f]{2}[:-]){5}/)) {
          return reject(new Error('Invalid mac address specified'))
        }
      }

      self._apiRequest({ method: 'POST', path: `/s/${site}/stat/device` }, JSON.stringify({ macs }))
        .then(response => {
          resolve(response.data.data)
        })
        .catch(error => {
          reject(error)
        })
    })
  }

  /**
   * Get events
   * @param {object} [options] - Filter options.
   * @param {number} [options.start] - First event to return, default is 0.
   * @param {number} [options.limit] - Number of events to return, default is 100.
   * @param {number} [options.period] - Period specified in hours, default is 1.
   * @param {string} [site] - The site for which return the events, default is 'default'
   * @return {object[]} Each event is represented by an object containing all relevant properties.
   */
  getEvents (options = {}, site = 'default') {
    var self = this

    logger.silly('UnifiController.getEvents: Entering')

    return new Promise((resolve, reject) => {
      if (typeof options === 'string') {
        site = options
        options = {}
      }

      const filter = {
        _start: options.start > 0 ? options.start : 0,
        _limit: options.limit > 0 ? options.limit : 100,
        within: options.period > 1 ? options.period : 1
      }

      self._apiRequest({ method: 'POST', path: `/s/${site}/stat/event` }, filter)
        .then(response => {
          resolve(response.data.data)
        })
        .catch(error => {
          reject(error)
        })
    })
  }

  /**
   * Get a list of sites managed by this controller.
   * @param {string} [site] - The site for which return the events, default is 'default'
   * @return {object[]} A list of objects is returned. Each object represents the properties of a site.
   */
  getHealth (site = 'default') {
    var self = this

    logger.silly('UnifiController.getHealth: Entering')

    return new Promise((resolve, reject) => {
      self._apiRequest({ method: 'GET', path: `/s/${site}/stat/health` })
        .then(response => {
          resolve(response.data.data)
        })
        .catch(error => {
          reject(error)
        })
    })
  }

  /**
   * Get a list of rogue access points.
   * @param {object} [options] - Filter options.
   * @param {number} [options.limit] - Number of events to return, default is 100.
   * @param {number} [options.period] - Period specified in hours, default is 1.
   * @param {string} [site] - The site for which return the rogue accept points, default is 'default'
   * @return {object[]} A list of objects representing each rogue access point is returned.
   */
  getRogueAP (options = {}, site = 'default') {
    var self = this

    logger.silly('UnifiController.getRogueAP: Entering')

    return new Promise((resolve, reject) => {
      if (typeof options === 'string') {
        site = options
        options = {}
      }

      const filter = {
        _limit: options.limit > 0 ? options.limit : 100,
        within: options.period > 1 ? options.period : 1
      }

      self._apiRequest({ method: 'POST', path: `/s/${site}/stat/rogueap` }, filter)
        .then(response => {
          resolve(response.data.data)
        })
        .catch(error => {
          reject(error)
        })
    })
  }

  /**
   * Get a list of routes for a site.
   * @param {string} [site] - The site for which return the events, default is 'default'
   * @return {object[]} A list of objects representing each route is returned.
   */
  getRoutes (site = 'default') {
    var self = this

    logger.silly('UnifiController.getRoutes: Entering')

    return new Promise((resolve, reject) => {
      self._apiRequest({ method: 'GET', path: `/s/${site}/stat/routing` })
        .then(response => {
          resolve(response.data.data)
        })
        .catch(error => {
          reject(error)
        })
    })
  }

  /**
   * Get a list of sites managed by this controller (incl. statistics).
   * @return {object[]} A list of objects is returned. Each object represents the properties of a site.
   */
  getSites () {
    var self = this

    logger.silly('UnifiController.getSites: Entering')

    return new Promise((resolve, reject) => {
      self._apiRequest({ method: 'GET', path: '/stat/sites' })
        .then(response => {
          resolve(response)
        })
        .catch(error => {
          reject(error)
        })
    })
  }

  /**
   * Get a list of sites managed by this controller
   * @return {object[]} A list of objects is returned. Each object represents the properties of a site.
   */
  getSystemInfo (site = 'default') {
    var self = this

    logger.silly('UnifiController.getHealth: Entering')

    return new Promise((resolve, reject) => {
      self._apiRequest({ method: 'GET', path: `/s/${site}/stat/sysinfo` })
        .then(response => {
          resolve(response.data.data)
        })
        .catch(error => {
          reject(error)
        })
    })
  }

  /**
   * Start a websocket listener
   */
  startWebsocketListener () {
    var self = this

    logger.silly('UnifiController.startWebsocketListener: Entering')

    return new Promise(async (resolve, reject) => {
      if (!self._session) {
        try {
          await self._authenticate()
        } catch (error) {
          return reject(error)
        }
      }

      self.wss = new WebSocketClient(`${self.baseURL.replace(/^http?:/, 'wss')}/wss/s/${self.site}/events`, {
        rejectUnauthorized: false,
        headers: {
          Cookie: `unifises=${self._session};`
        }
      })

      self.wss.on('open', () => {
        logger.debug('UnifiController.startWebsocketListener: Connected')
        resolve()
      })

      self.wss.on('message', msg => {
        logger.silly(`UnifiController.startWebsocketListener: Received ${msg}`)

        try {
          msg = JSON.parse(msg)
        } catch (error) {
          logger.error(`UnifiController.startWebsocketListener: Received non-JSON message (${error})`)
          return
        }

        if (msg.meta.message === 'events') {
          // Wireless User Events:
          // EVT_WU_Connected - Wireless User connected
          // EVT_WU_Disconnected - Wireless User disconnected
          // EVT_WU_ROAM - Wireless User roamed from one AP to another
          // EVT_WU_ROAM_RADIO - Wireless User changed channel on the same AP

          // Wireless Guest Events:
          // EVT_WG_Connected - Wireless Guest connected
          // EVT_WG_Disconnected - Wireless Guest disconnected
          // EVT_WG_ROAM - Wireless Guest roamed from one AP to another
          // EVT_WG_ROAM_RADIO - Wireless Guest changed channel on the same AP
          // EVT_WG_AUTHORIZATION_ENDED - Wireless Guest became unauthorised

          // LAN User Events:
          // EVT_LU_CONNECTED - LAN User connected to the network
          // EVT_LU_DISCONNECTED - LAN User disconnected from the network

          // LAN Guest Events:
          // EVT_LG_CONNECTED - LAN Guest connected to the network
          // EVT_LG_DISCONNECTED - LAN Guest disconnected from the network
          msg.data.forEach(event => {
            logger.debug(`UnifiController.startWebsocketListener: Emit ${event.key}`)
            logger.error(JSON.stringify(event))
            self.emit(event.key, event)
          })
        } else {
          // device.sync
          // sta.sync
          logger.debug(`UnifiController.startWebsocketListener: Emit ${msg.meta.message}`)

          self.emit(msg.meta.message, msg.data)
        }
      })

      self.wss.on('close', () => {
        logger.debug('UnifiController.startWebsocketListener: Socket closed')
      })

      self.wss.on('error', error => {
        logger.error(`UnifiController.startWebsocketListener: ${JSON.stringify(error)}`)
      })
    })
  }
}
