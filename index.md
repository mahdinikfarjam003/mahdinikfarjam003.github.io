---
layout: default
title: Home
---

# MMC20 Security Research Blog

Welcome to my security research and detection engineering blog.

Here you can find:

- Windows Lateral Movement research
- Detection Engineering content
- Splunk / SIEM use cases
- MITRE ATT&CK analysis
- Proof of Concepts (PoC)

---

## Latest Articles

<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a> - {{ post.date | date: "%Y-%m-%d" }}
    </li>
  {% endfor %}
</ul>
