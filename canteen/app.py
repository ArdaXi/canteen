import logging
import socket
import re
import time
from threading import Thread
from Queue import Queue

banner_regex = re.compile("Asterisk Call Manager\/(([0-9]\.?)+)")

class Canteen():

  def __init__(self, address, username, password):
    self.logger = logging.getLogger(__name__)
    self.responses = Queue()
    self.event_handlers = {}
    self.outstanding_actions = []
    self._connect(address)
    self._authenticate(username, password)
    self.eventloop = self.EventLoop(self)
    self.eventloop.start()
    
  def _connect(self, address):
    self.logger.info("Connecting to %s", address)
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock.connect(address)
    self.conn_file = self.sock.makefile('r+', 0)

  def _authenticate(self, username, password):
    self.logger.info("Authenticating as %s with password %s", username, "*****")
    banner = self.conn_file.readline()
    match = banner_regex.match(banner)
    if not match:
      raise IOError("Invalid banner; expected '{}', received '{}'"
                    .format("Asterisk Call Manager/X", banner))
    self.remote_version = match.group(1)
    login_action = {"Action": "Login", "Username": username, "Secret": password}
    self._action(login_action)
    result = self._read_packet()
    if not "Response" in result or result["Response"] != "Success":
      raise RuntimeError(str(result))
    self.logger.info(result["Message"])
  
  def _action(self, data):
    self.logger.debug("Sending packet:")
    action_id = str(time.time())
    data["ActionID"] = action_id
    for item in data.iteritems():
      line = "{}: {}\r\n".format(item[0], item[1])
      self.conn_file.write(line)
      self.logger.debug(line.rstrip())
    self.conn_file.write("\r\n")
    self.outstanding_actions.append(action_id)
    return action_id

  def _read_packet(self):
    self.logger.debug("Receiving message:")
    result = {}
    while True:
      line = self.conn_file.readline().rstrip()
      if not line:
        if "ActionID" in result:
          self.outstanding_actions.remove(result["ActionID"])
        return result
      self.logger.debug(line)
      key, val = line.split(": ", 1)
      result[key] = val

  def _dispatch_packet(self, packet):
    if "Response" in packet:
      self.logger.debug("Stored response.")
      self.responses.put(packet)
    elif "Event" in packet:
      event = packet["Event"]
      if event in self.event_handlers:
        self.logger.debug("Dispatching handler for event: %s", event)
        t = Thread(target=self.event_handlers[event], args=(packet,))
        t.start()
      else:
        self.logger.debug("Ignoring event without handler: %s", event)

  def handle(self, event):
    def decorator(f):
      if event in self.event_handlers:
        raise Exception("Event {} already handled!".format(event))
      self.event_handlers[event] = f
      return f
    return decorator

  class EventLoop(Thread):
    def __init__(self, parent):
      Thread.__init__(self)
      self.parent = parent
      self.action_queue = Queue()
      self.daemon = True

    def run(self):
      self.parent.sock.setblocking(1)
      while True:
        if (not self.action_queue.empty() and
            len(self.parent.outstanding_actions) == 0):
          action = self.action_queue.get()
          self.parent._action(action)
        self.parent._dispatch_packet(self.parent._read_packet())
