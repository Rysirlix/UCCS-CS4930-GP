# Kickoff

We aim to build a cookie and consent auditor for websites. Users will input a website URL, and the application/tool will scan the site to identify cookies, track their duration, and determine which ones may serve tracking or advertising purposes. The tool will generate a report (HTML, PDF, or CSV) that lists cookies, provides metadata, and assigns a basic privacy score.

## Project Structure


## Project Plan

- **Task List**:
  - `Project Setup & Research`
    - Research cookie auditing methods & existing tools
    - Decide on tech stack (I.E. requests vs Selenium, reporting format)
    - Github repository already created
  - `Core Development`
    - Implement cookie scanner (fetch cookies, domains, expiry, flags)
    - Implement cookie classification (session vs persistent, tracker identification)
    - Build report generator (CSV, HTML, PDF)
  - `Web Interface`
    - Develop flask frontend (simple form to enter URL)
    - Display results in browser
    - Allow export of reports
  - `Privacy Scoring System`
    - Define scoring criteria (numbers of trackers, persistence length, secure flags)
    - Implement automated score calculation
    - Display/explain score in reports
  - `Testing & Debugging`
    - Test with popular websites (as permitted) new, e-commerce, social media
    - Verify cookie detection accuracy
    - Fix bugs and optimize performance
  - `Documentation & Presentation`
    -  Write user instructions
    -  Prepare project reports/slides
    -  practice /demo presentation
  
- **Task Assignment**:
  - `Reese N.`: Example-(ML & Backend)
  - `Maxwell H.`:(blank)
  - `Matthew H.`:(blank)

- **Timeline**:
  - `Example Dates`:
    - Week 1-2:
      - Research cookie auditing methods, finalize tech stack
    - Week 3-4:
      - Build cookie scanner prototype (fetch
    - Week 5:
      - Extended scanner (session vs persistent cookies, tracker detection basic)
    - Week 6:
      - Report generator (CSV output first, then HTML/PDF)
    - Week 7:
      - Flask interface prototype (URL input, display raw cookie data)
    - Week 8-9:
      - Privacy scoring system: define criteria + implement logic
    - Week 10:
      - Integration: scanner + scoring + reporting + Flask
    - Week 11:
      - Testing with mult websites (social, e-commerce, news, etc.) adjust scoring
    - Week 12:
      - Buffer week: bug fixes, performance tweaks, optional features (crawling, auto-labeling)
    - Week 13:
      - Documentation: user guide, technical write-up
    - Week 14:
      - Final polish: prepare slides/presentation, last-minute fixes
    - `OpenAI` - Requests GPT 4o to estimate airport security queue time for a flight
      - Swagger Documentation for OpenAI integration endpoints can be viewed on app route /api/openai/swagger/ 

- **Accountability plan**:
  - `Weekly check-ins`: 30–45 min, status + blockers.

## Gantt Chart

**************

### Project Management Notes:

If time permits, we may add extended features such as:
  - Crawling multiple pages
  - Automatically labeling cookie types (analytics, advertising, functional)
  - Providing explanations and notes on privacy scoring
