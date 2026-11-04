# Third-party notices

The Shopify crawler-access wire format and signature-base implementation adapt the MIT-licensed OpenSEO implementation at [every-app/open-seo@89e5a00717cdf049b7c2b4e29646edb3a7d4995b](https://github.com/every-app/open-seo/tree/89e5a00717cdf049b7c2b4e29646edb3a7d4995b), specifically src/shared/crawler-access.ts and src/server/features/audit/services/shopifySignature.ts. Ten98 adds strict bounded parsing and exact-origin selection; application credential and request lifecycles are separate.

The local Lighthouse report normalizer adapts metric mappings, severity thresholds and compact issue/detail projection from the same OpenSEO commit's `src/server/lib/lighthouseStoredPayload.ts`. Ten98 adds requested-URL binding, bounded scalar-only details, explicit missing/error/truncation evidence and local Lighthouse 13.6.0 report validation. Provider billing fields are omitted. The upstream MIT notice below applies to both adaptations. The local report contract was checked against [GoogleChrome/lighthouse@edc407d72179bbc4d4de8a40ef0311ca87dff89c](https://github.com/GoogleChrome/lighthouse/tree/edc407d72179bbc4d4de8a40ef0311ca87dff89c); this runtime package does not bundle Lighthouse or Chromium.

MIT License

Copyright (c) 2026 Ben Senescu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
