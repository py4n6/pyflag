""" This module deals with webmail generically.

The way webmail is parsed within PyFlag is as follows:

- Each message is a new object (The data may correspond with the main
text part of the message or it may be empty, it is also an anchor
point for part objects. The URN of the message object is made unique
by way of the message id (most webmail services have a way to indicate
a unique id for each message).

- The message object contains the following database table entry:
   From email, to email, subject, sent, type, service

- Parts are specific object attachments or parts. Attachments are
usually also parts.
"""
