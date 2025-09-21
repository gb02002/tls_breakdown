# README.md  

I made this codebase in order to understand how exactly the protocol is implemented and where is 'security' buried.  
In short - a trusted 3rd party makes the music.

## Concept

### 2 problems

Basically, for non-cbs the idea of having a **pre-existing** secured channel seems viable. Some math here and there, and if you haven't witnessed and sniffed the negotiation part there is nothing you can do: gpg, hashes, XORs, rainbow tables, salt - it's all well known, there is no magic.
So moving to the web, knowing you can have something 'secured', new problems arise: how to make this first contact on obviously unsecure channel?  

### Negotiation for sake of security  

Imagine you agreed with your counterpart on a large, common number, say 300. You have a=5 and a\`=a*300=1500, and your counterpart has b=7 and b\`=b*300=2100. You give a\` and receive b\`. Each side has no original(a and b) of it's counterpart. Now each side simply gets same end result from respective multiplication, as a\*b\`*300 \=\= b\*a\`*300 \=\= 10500.  
Generally it's called Diffie–Hellman key exchange and according wikipage covers the concept pretty well.  
Now we know, that it is possible to exchange 2 public keys between two sides without being exposed.

### CA

MITM  
So far is all cool and shiny, but for now even though your connection it secured from outsider perspective, you actually have no idea who you speak with(owl joke). Initially you may have negotiated with the fake counterpart. Your round of discussions may have been made with random man-in-the-middle. He could have give you and your authentic counterpart his keys, and trick you both. He receives encrypted message from you, decrypts it, reads, encrypts with second pair of keys and sends to your counterpart.  
Here is where the CA certificates come into play.

### Final reasoning

Basically, there are no way to establish a secure connection without having any prior knowledge or agreements and be sure the second side is authentic, simply because: well, they all look the same(no prior knowledge). Hence, you must rely on a trusted third authority that can vouch for your counterpart's authenticity. Now you have prior knowledge.

## Code

### Setting up

Everything is straightforward, although if you lack python knowledge, here is the ritual:

1. For good system: `bash which python3` and `bash where python` for the other one
2. Summon virtual environment: `bash python -m venv .venv` && `bash source .venv/bin/activate`
3. Pull deps: `pip install -r requirements.txt`

### Educational running part

1. Run `python src/server/server.py` to lock socket and accept connections
2. Run `python src/client/client.py` in second terminal to connect and send your important message

6. You can also use socat to become real mitm. Port to sniff is displayed on server startup.
