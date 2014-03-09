# Monkey Streams

Streams are an interface to distribute data from different sources
through a Channel that have an end-point as a consumer

## Streams

A stream have a type to define an input source, the available options
at the moment would be:

   - Raw data from buffer
   - Static File
   - IOV array (mk_iov implementation)

For short a Stream is an Input plus a context to manage offsets and handlers
for special behaviors such as errors or connection drops.

A Stream requires an end point, this end-point is represented by a Channel.

## Channels

A Channel is a handling interface for an end-point, where it can be a plain
socket, some socket library such as SSL or other. The Channel flush the
Stream content and is the one in charge to maintain connection.


## Workflow

 1. Requestor create a Stream
 2. Requestor set content for the Stream
 3. Requestor get the channel and associate the Stream to it
 4. Requestor put the Channel to flush content from the Stream.

