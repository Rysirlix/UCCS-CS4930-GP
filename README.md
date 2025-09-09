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
    - Sep 8–12: Task 1
    - Sep 8–15: Task 2
    - Sep 15–29: Task 3
    - Sep 22–Oct 6: Task 4
    - Sep 29–Oct 13: Task 5
    - Oct 6–13: Task 7
    - Oct 6–20: Task 6
    - Oct 13–27: Task 8
    - Sep 15–Oct 1: Task 9
    - Oct 27–Nov 10: Task 11
    - Nov 3–Nov 10: Task 10
    - Nov 10–Nov 24: Task 12
    - Nov 24–Dec 5: Task 13
    - Dec 5–Dec 12: Task 14
- **Accountability plan**:
  - `Weekly check-ins`: 30–45 min, status + blockers.

## Gantt Chart

**************

### Project Management Notes:

If time permits, we may add extended features such as:
  - Crawling multiple pages
  - Automatically labeling cookie types (analytics, advertising, functional)
  - Providing explanations and notes on privacy scoring
