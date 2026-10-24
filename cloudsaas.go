package main

// Cloud / SaaS sprawl discovery.
//
// Everything here is derived from DNS answers the scan already holds, so it sends no extra
// traffic. A name that is an alias for a cloud platform, an SPF "include:" that authorises a
// mail service, an MX record, or a domain-verification TXT token all prove the organisation
// uses that service. The result is an inventory (new services raise an event) and a finding
// when a managed database, cache or search cluster has a name in public DNS.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Cloud service categories.
const (
	catCloud     = "Cloud hosting"
	catAPI       = "API & serverless"
	catData      = "Database & storage"
	catSaaS      = "SaaS application"
	catMail      = "Email service"
	catCDN       = "CDN & edge"
	catIdentity  = "Identity & verification"
	catSupport   = "Support & marketing"
	catDevtools  = "Developer platform"
	datastoreCat = catData
)

type cloudSig struct{ Suffix, Provider, Category string }

// cnameSigs match a CNAME target (or host name) by domain suffix.
var cnameSigs = []cloudSig{
	{"execute-api.", "AWS API Gateway", catAPI}, {"lambda-url.", "AWS Lambda", catAPI},
	{"cloudfront.net", "AWS CloudFront", catCDN}, {"elb.amazonaws.com", "AWS Load Balancer", catCloud},
	{"elasticbeanstalk.com", "AWS Elastic Beanstalk", catCloud}, {"s3.amazonaws.com", "AWS S3", catData},
	{"amazonaws.com", "AWS", catCloud},
	{"azure-api.net", "Azure API Management", catAPI}, {"azurewebsites.net", "Azure App Service", catCloud},
	{"azurefd.net", "Azure Front Door", catCDN}, {"azureedge.net", "Azure CDN", catCDN},
	{"trafficmanager.net", "Azure Traffic Manager", catCloud}, {"blob.core.windows.net", "Azure Blob Storage", catData},
	{"cloudapp.azure.com", "Azure VM", catCloud}, {"azurecontainerapps.io", "Azure Container Apps", catCloud},
	{"cloudfunctions.net", "Google Cloud Functions", catAPI}, {"run.app", "Google Cloud Run", catAPI},
	{"appspot.com", "Google App Engine", catCloud}, {"storage.googleapis.com", "Google Cloud Storage", catData},
	{"web.app", "Firebase Hosting", catCloud}, {"firebaseapp.com", "Firebase Hosting", catCloud},
	{"herokuapp.com", "Heroku", catCloud}, {"netlify.app", "Netlify", catCloud}, {"vercel.app", "Vercel", catCloud},
	{"github.io", "GitHub Pages", catDevtools}, {"pages.dev", "Cloudflare Pages", catCloud}, {"workers.dev", "Cloudflare Workers", catAPI},
	{"fastly.net", "Fastly", catCDN}, {"akamaiedge.net", "Akamai", catCDN}, {"edgekey.net", "Akamai", catCDN},
	{"digitaloceanspaces.com", "DigitalOcean Spaces", catData}, {"ondigitalocean.app", "DigitalOcean App Platform", catCloud},
	{"zendesk.com", "Zendesk", catSupport}, {"freshdesk.com", "Freshdesk", catSupport}, {"statuspage.io", "Atlassian Statuspage", catSaaS},
	{"atlassian.net", "Atlassian Cloud", catSaaS}, {"hubspot.net", "HubSpot", catSupport}, {"hs-sites.com", "HubSpot", catSupport},
	{"mktoweb.com", "Marketo", catSupport}, {"salesforce.com", "Salesforce", catSaaS}, {"force.com", "Salesforce", catSaaS},
	{"my.salesforce-sites.com", "Salesforce Sites", catSaaS}, {"shopify.com", "Shopify", catSaaS}, {"myshopify.com", "Shopify", catSaaS},
	{"wpengine.com", "WP Engine", catCloud}, {"readme.io", "ReadMe", catSaaS}, {"intercom.io", "Intercom", catSupport},
	{"okta.com", "Okta", catIdentity}, {"auth0.com", "Auth0", catIdentity}, {"sendgrid.net", "SendGrid", catMail},
	{"mailgun.org", "Mailgun", catMail}, {"mcsv.net", "Mailchimp", catMail}, {"sharepoint.com", "Microsoft 365 SharePoint", catSaaS},
	{"ghost.io", "Ghost", catSaaS}, {"pantheonsite.io", "Pantheon", catCloud}, {"surge.sh", "Surge", catCloud},
	{"bitbucket.io", "Bitbucket Pages", catDevtools}, {"gitlab.io", "GitLab Pages", catDevtools},
}

// datastoreSigs are managed databases, caches and search clusters. A name pointing at one is
// worth a look: these should normally be reachable only from inside a private network.
var datastoreSigs = []cloudSig{
	{"rds.amazonaws.com", "AWS RDS", datastoreCat}, {"redshift.amazonaws.com", "AWS Redshift", datastoreCat},
	{"cache.amazonaws.com", "AWS ElastiCache", datastoreCat}, {"docdb.amazonaws.com", "AWS DocumentDB", datastoreCat},
	{"es.amazonaws.com", "AWS OpenSearch", datastoreCat}, {"database.windows.net", "Azure SQL", datastoreCat},
	{"postgres.database.azure.com", "Azure PostgreSQL", datastoreCat}, {"mysql.database.azure.com", "Azure MySQL", datastoreCat},
	{"redis.cache.windows.net", "Azure Cache for Redis", datastoreCat}, {"documents.azure.com", "Azure Cosmos DB", datastoreCat},
	{"mongodb.net", "MongoDB Atlas", datastoreCat}, {"redislabs.com", "Redis Cloud", datastoreCat}, {"redns.redis-cloud.com", "Redis Cloud", datastoreCat},
	{"found.io", "Elastic Cloud", datastoreCat}, {"elastic-cloud.com", "Elastic Cloud", datastoreCat}, {"es.io", "Elastic Cloud", datastoreCat},
	{"firebaseio.com", "Firebase Realtime Database", datastoreCat}, {"supabase.co", "Supabase", datastoreCat},
	{"db.ondigitalocean.com", "DigitalOcean Managed DB", datastoreCat}, {"neon.tech", "Neon Postgres", datastoreCat},
	{"cockroachlabs.cloud", "CockroachDB Cloud", datastoreCat}, {"planetscale.com", "PlanetScale", datastoreCat},
}

// spfSigs map an SPF include: domain to the mail service it authorises.
var spfSigs = []cloudSig{
	{"_spf.google.com", "Google Workspace", catMail}, {"spf.protection.outlook.com", "Microsoft 365 Exchange", catMail},
	{"sendgrid.net", "SendGrid", catMail}, {"mailgun.org", "Mailgun", catMail}, {"amazonses.com", "Amazon SES", catMail},
	{"servers.mcsv.net", "Mailchimp", catMail}, {"mandrillapp.com", "Mandrill", catMail}, {"spf.mtasv.net", "Postmark", catMail},
	{"mailjet.com", "Mailjet", catMail}, {"salesforce.com", "Salesforce", catSaaS}, {"zendesk.com", "Zendesk", catSupport},
	{"hubspot.com", "HubSpot", catSupport}, {"freshdesk.com", "Freshdesk", catSupport}, {"_spf.atlassian.net", "Atlassian", catSaaS},
	{"pphosted.com", "Proofpoint", catMail}, {"mimecast.com", "Mimecast", catMail}, {"zoho.com", "Zoho", catSaaS},
	{"spf.sendinblue.com", "Brevo (Sendinblue)", catMail}, {"helpscoutemail.com", "Help Scout", catSupport},
	{"intercom.io", "Intercom", catSupport}, {"servers.outlook.com", "Microsoft 365", catMail},
}

// mxSigs map an MX host suffix to the mail service.
var mxSigs = []cloudSig{
	{"google.com", "Google Workspace", catMail}, {"googlemail.com", "Google Workspace", catMail},
	{"mail.protection.outlook.com", "Microsoft 365 Exchange", catMail}, {"pphosted.com", "Proofpoint", catMail},
	{"mimecast.com", "Mimecast", catMail}, {"zoho.com", "Zoho Mail", catMail}, {"messagingengine.com", "Fastmail", catMail},
	{"protonmail.ch", "Proton Mail", catMail}, {"barracudanetworks.com", "Barracuda", catMail}, {"mailgun.org", "Mailgun", catMail},
}

// txtSigs map a domain-verification TXT prefix (SaaS onboarding leaves these behind) to the service.
var txtSigs = []struct{ Prefix, Provider, Category string }{
	{"google-site-verification=", "Google (Search Console / Workspace)", catIdentity}, {"ms=ms", "Microsoft 365", catIdentity},
	{"atlassian-domain-verification=", "Atlassian Cloud", catSaaS}, {"docusign=", "DocuSign", catSaaS},
	{"facebook-domain-verification=", "Meta (Facebook)", catSupport}, {"apple-domain-verification=", "Apple Business", catIdentity},
	{"stripe-verification=", "Stripe", catSaaS}, {"slack-domain-verification=", "Slack", catSaaS},
	{"zoom-domain-verification=", "Zoom", catSaaS}, {"adobe-idp-site-verification=", "Adobe", catSaaS},
	{"onetrust-domain-verification=", "OneTrust", catSaaS}, {"dropbox-domain-verification=", "Dropbox", catSaaS},
	{"shopify-verification-code=", "Shopify", catSaaS}, {"hubspot-developer-verification=", "HubSpot", catSupport},
	{"miro-verification=", "Miro", catSaaS}, {"asana-verification=", "Asana", catSaaS}, {"canva-site-verification=", "Canva", catSaaS},
	{"box-domain-verification=", "Box", catSaaS}, {"github-challenge-", "GitHub", catDevtools}, {"gitlab-pages-verification-code=", "GitLab", catDevtools},
	{"figma-domain-verification=", "Figma", catSaaS}, {"notion-domain-verification=", "Notion", catSaaS},
	{"smartsheet-site-validation=", "Smartsheet", catSaaS}, {"mongodb-site-verification=", "MongoDB Atlas", catData},
	{"cloudflare-verify", "Cloudflare", catCDN}, {"amazonses:", "Amazon SES", catMail}, {"openai-domain-verification=", "OpenAI", catSaaS},
	{"anthropic-domain-verification-", "Anthropic", catSaaS}, {"postman-domain-verification=", "Postman", catDevtools},
	{"airtable-verification=", "Airtable", catSaaS}, {"webexdomainverification.", "Cisco Webex", catSaaS},
}

// CloudService is one provider the organisation was seen to use.
type CloudService struct {
	Provider string   `json:"provider"`
	Category string   `json:"category"`
	Via      string   `json:"via"` // cname, spf, mx, txt
	Hosts    []string `json:"hosts"`
	Data     bool     `json:"-"` // a managed datastore published in DNS
}

func matchSuffix(sigs []cloudSig, name string) *cloudSig {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	var best *cloudSig
	for i := range sigs {
		s := sigs[i].Suffix
		if n == s || strings.HasSuffix(n, "."+s) || (strings.HasSuffix(s, ".") && strings.Contains(n, "."+s)) || (strings.HasPrefix(n, s) && strings.HasSuffix(s, ".")) {
			if best == nil || (strings.HasSuffix(s, ".") && !strings.HasSuffix(best.Suffix, ".")) || (strings.HasSuffix(s, ".") == strings.HasSuffix(best.Suffix, ".") && len(s) > len(best.Suffix)) {
				best = &sigs[i]
			}
		}
	}
	return best
}

// detectCloud inventories the cloud and SaaS services visible in the DNS results.
func detectCloud(_ string, hosts []string, results map[string]*HostResult) []CloudService {
	type key struct{ p, c string }
	inv := map[key]*CloudService{}
	add := func(p, c, via, host string, data bool) {
		k := key{p, c}
		cs := inv[k]
		if cs == nil {
			cs = &CloudService{Provider: p, Category: c, Via: via}
			inv[k] = cs
		}
		cs.Data = cs.Data || data
		for _, h := range cs.Hosts {
			if h == host {
				return
			}
		}
		cs.Hosts = append(cs.Hosts, host)
	}
	for _, h := range hosts {
		hr := results[h]
		if hr == nil || hr.NX {
			continue
		}
		targets := append([]string{}, hr.Records["CNAME"]...)
		if hr.Dangling != "" {
			targets = append(targets, hr.Dangling)
		}
		for _, t := range targets {
			if d := matchSuffix(datastoreSigs, t); d != nil {
				add(d.Provider, d.Category, "cname", h, true)
			} else if c := matchSuffix(cnameSigs, t); c != nil {
				add(c.Provider, c.Category, "cname", h, false)
			}
		}
		for _, mx := range hr.Records["MX"] {
			f := strings.Fields(mx)
			if len(f) == 0 {
				continue
			}
			if m := matchSuffix(mxSigs, f[len(f)-1]); m != nil {
				add(m.Provider, m.Category, "mx", h, false)
			}
		}
		for _, txt := range hr.Records["TXT"] {
			low := strings.ToLower(strings.Trim(strings.TrimSpace(txt), `"`))
			if strings.HasPrefix(low, "v=spf1") {
				for _, tok := range strings.Fields(low) {
					if inc, ok := strings.CutPrefix(tok, "include:"); ok {
						if m := matchSuffix(spfSigs, inc); m != nil {
							add(m.Provider, m.Category, "spf", h, false)
						}
					}
				}
				continue
			}
			for _, sg := range txtSigs {
				if strings.HasPrefix(low, sg.Prefix) {
					add(sg.Provider, sg.Category, "txt", h, false)
					break
				}
			}
		}
	}
	out := make([]CloudService, 0, len(inv))
	for _, cs := range inv {
		sort.Strings(cs.Hosts)
		out = append(out, *cs)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}

func cloudViaText(via string) string {
	switch via {
	case "cname":
		return "a DNS alias"
	case "spf":
		return "its SPF record"
	case "mx":
		return "its MX record"
	case "txt":
		return "a domain-verification record"
	}
	return via
}

func cloudDetail(cs CloudService) string {
	hs := cs.Hosts
	extra := ""
	if len(hs) > 3 {
		extra = fmt.Sprintf(" and %d more", len(hs)-3)
		hs = hs[:3]
	}
	return fmt.Sprintf("%s (%s) is in use, seen through %s on %s%s", cs.Provider, strings.ToLower(cs.Category), cloudViaText(cs.Via), strings.Join(hs, ", "), extra)
}

func cloudInvKey(root string) string { return "cloudinv:" + root }

// loadCloudInventory returns the services saved by the previous scan (nil if none).
func loadCloudInventory(st *Store, root string) []CloudService {
	v, ok, err := st.getMeta(cloudInvKey(root))
	if err != nil || !ok {
		return nil
	}
	var inv []CloudService
	if json.Unmarshal([]byte(v), &inv) != nil {
		return nil
	}
	return inv
}

// applyCloud saves the inventory, reports services not seen before and flags public datastores.
func (s *Scanner) applyCloud(tx *Tx, root string, cur, prev []CloudService,
	emit func(kind, sev, host, detail string, inventory bool),
	raise func(key, kind, sev, host, detail, source string)) error {
	known := map[string]bool{}
	for _, p := range prev {
		known[p.Provider+"|"+p.Category] = true
	}
	for _, cs := range cur {
		if !known[cs.Provider+"|"+cs.Category] {
			emit("cloud-service", "info", cs.Hosts[0], cloudDetail(cs), true)
		}
		if cs.Data {
			for _, h := range cs.Hosts {
				raise("clouddb:"+h+":"+cs.Provider, "cloud-datastore", "medium", h,
					fmt.Sprintf("%s has a name in public DNS that points at %s, a managed database, cache or search service. The name alone does not make it reachable, but such services are often left open to the internet by mistake", h, cs.Provider), "")
			}
		}
	}
	b, err := json.Marshal(cur)
	if err != nil {
		return err
	}
	return tx.SetMeta(cloudInvKey(root), string(b))
}
