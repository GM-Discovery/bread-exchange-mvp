# **Welcome to Helm Poll**
![License](https://img.shields.io/github/license/GM-Discovery/bread-exchange-mvp)
![Release](https://img.shields.io/github/v/release/GM-Discovery/bread-exchange-mvp)
![Status](https://img.shields.io/badge/status-MVP-blue)

### Weighted voting • Delegated voting • Federated exchanges

## (A voting app devoted to trust) 

Install instructions way below, at the bottom, last thing if you're skipping to the fun part.
 → [Jump to Install](#install)

<img width="438" height="432" alt="image" src="https://github.com/user-attachments/assets/02c99c8f-aec7-471b-9a39-c059d1119ee1" />

I'm Grant, btw. The creator of this "app."

Technically, this is the "bread-exchange-mvp" stack that operates Helm Poll. It's kind of a long story, but here goes:

**Why Bread?** - Because everyone should eat, and everyone should have a voice in governance. See https://github.com/GM-Discovery/The-Bread-Standard for more details.

The backend (the Exchange) is an aggregator of polls, personas, weights, representations, and identities, and, above all, trust.

So, bread-exchange-mvp because I learned too late changing the names of my repo and folders messes things up later.

But... Helm Poll is what people see when they use the app and that's what I like to call the GUI (Graphic User Interface) or 'frontend.' 

---

## What this app does:

It lets you make polls and vote in those polls. 

And post those polls to an exchange where others can vote on your polls and give you theirs to vote on. Here are some highlighted features:

##### Weighted Results 
A farmer should have a bigger vote when it's time to decide how we're dividing shared water, because we need the food.
A doctor should have a bigger vote than a shareholder when it's time to decide what is medically necessary.
You should have a bigger vote when you are an expert in an issue, when you are affected directly by the result, or if are accountable to the results, or when the exchange recognizes a rule that grants weight.

So some people might vote with more weight than others.
While others still might have weight from representing other people that cannot or do not cast their vote directly.

##### Liquid Democracy 
Don't want to vote on every single thing, but still want to make sure someone is voting on your behalf for the things you believe in - Delegate your vote.
And if they don't vote the way you want, you can override them to make sure you always vote the way you want to.

##### Pseudonymous Voting 
The Exchange uses hashing and auditable records to protect privacy while preserving reviewability.

---

## TRUST

Everything is auditable. 
System operators can audit the records used to calculate results to ensure that your vote was there and weighted correctly.

More technical details about how this app does these things below.

I know what you're thinking: Who decides who gets to have bigger votes when it comes time to vote?

The Exchange running the poll applies whatever weighting rules that Exchange recognizes for that kind of decision.

Anyone can host an Exchange. Anyone that hosts the exchange gets a key that lets them put weights into the exchange along with a reason.
Each exchange decides which authorities and qualifiers it recognizes. Moreover, it's a code. An authority hash + qualifier tag.
Then anyone that has the code can be called upon for their expertise or weighted more heavily in a greater vote.
And qualifiers are when they allow that weight or not.
So at scale it is a social construct, whatever society says the weight should come from.

At the individual level, it is open source so anyone can make it do anything and give points for whatever reason. So it is important to associate only with exchanges you trust.

---

### Very technical notes:

Helm Poll is intentionally simple.

<details>
  <summary>Architecture</summary>


```
User

  │

  ▼

Helm Poll UI (static frontend)

  │

  ▼

Bread Exchange API (Node / Express)

  │
 
  ▼

Exchange data store
```
</details>

#### Components

##### Helm Poll UI

create polls

vote in polls

share polls with other exchanges

view results

##### Bread Exchange

The Exchange is the record system behind Helm Poll.

It manages:

polls

identities

vote weight

delegations

trust stamps

Federation

Exchanges can share polls with each other.

Each exchange decides which other exchanges it trusts and which authorities it recognizes for assigning vote weight.

---

### Interested in hosting an Exchange?

You need three things - 

1. A server (I rented mine for very cheap on Hetzner when I built the system)

2. A domain. I rent breadstandard.com for cheap.

3. This app. Install instructions below.

#### Owning a server (or renting a VPS)
If you already own a server you can skip to Install below:

Servers are basically anything that connects to the internet and can host your apps.

REQUIRES UBUNTU 24.04 or similar modern Linux distribution.

So make sure your system can run that and Docker (should be auto-installed) + the app. The app is tiny, at MVP it was just barely less than 2MBs.

That said, the public record of polls and identities and stamps and such can get very long, I recommend pruning regularly or setting the configuration to auto-sheer.

But you don't need a strong server, I rented the cheapest one on Hetzner to build the thing when I started, less than $4 monthly, which is like half the cost of my regular loaf of bread.

And the internet, you need to connect your server to the net.

More details can be found in operator_notes.md in the top level folder (root) and after install a .env will be generated with your keys and identity.

After you have your server, you just need to point A and AAAA records at the server. 

This means opening DNS and adding a new record your subdomain name (I recommend exchange). 

Then the IPv4 and/or IPv6 addresses from your server into the DNS records and saving it.

It could take a short while for your DNS records to work.

---

### Parnterships and joining the network! 

Your identity and public key are in the generated .env.exchange file that will be generated for you automatically when you first install the file. Save that file someplace safe.

To see the network tab, use the operator key (everything after the equal sign on the line). Put that in the slot under settings where it asks for it and you'll get access to adding weights and the network tab.

You can add networks with their exchange id (ex_...) and their canonical URL (https://exchange.example.tld) and their Federation Public Key (B64 - also found in the .env.exchange file).

<img width="438" height="609" alt="image" src="https://github.com/user-attachments/assets/03fbc7c5-8690-4c29-8f35-f466af8dc15a" />

Once added you should see something like:

#### The network

<img width="442" height="527" alt="image" src="https://github.com/user-attachments/assets/2bbf47d4-fc55-45f9-a677-016e81eaa7e3" />

So, for example, The First Bread Exchange is has this information:

EXCHANGE_ID=ex_83c482bbe7d949028d09dca6

CANONICAL_BASE_URL=https://exchange.breadstandard.com

FEDERATION_PUBLIC_KEY_B64=MCowBQYDK2VwAyEA6GpsM0Kju4P1EBTnPPvLrHXDx+2aTAdjwiudcnfG4xw=

Never post your operator or private keys.

### Project Status

Helm Poll is currently an MVP.

Core functionality exists:

✓ poll creation

✓ weighted voting  

✓ delegation  

✓ exchange federation  

##### Planned development includes:

• stronger trust-weight frameworks  

• federation discovery  

• governance rule modules

### Roadmap

#### Short term
- stability improvements
- federation reliability
- clearer trust-weight tooling

#### Medium term
- discovery between exchanges
- governance rule modules
- improved delegation tools

#### Long term
- large-scale federation networks
- advanced trust weighting frameworks
- governance experimentation across exchanges

#### **Contributing | Get Involved**

You can join the discussion in the GitHub repository or join us on Discord at

https://discord.gg/zSkjykvy7g

### Security Notes

Helm Poll records votes, delegations, and weights as auditable records.

Results can be independently verified by reviewing the recorded data.

Operators should secure their servers and keys appropriately.
---
## Install instructions

You need to enter the terminal to your server and enter two commands.

#### Download the file

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/GM-Discovery/bread-exchange-mvp/v0.2.1/install.sh
```

#### Then, when you're ready to install, you can change the name of the command below to install, be sure to replace YOUR.DOMAIN.HERE in the command to your actual domain.

```
sudo bash install.sh --domain YOUR.DOMAIN.HERE --tag v0.2.1
```

After that, a "cron" will attempt to let you know of any updates automatically daily at 3am PST.

Thank you.
