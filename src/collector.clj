(ns collector
  (:gen-class)
  ;(:require [clojure.string :as str])
  ;Ovo proveri kako se importuje nece da radi kako treba
  ;(:import [clj_net_pcap Pcap])
  )

;F-ja koja cita podatke iz pcap fajla (resiti import)
;(defn read-and-print-pcap-simple
;  [pcap-file-path]
;  (println (str "--- Fajl path " pcap-file-path " ---"))
;
;  (Pcap/read pcap-file-path
;             (fn [packet]
;               (let [header (.getPcapHeader packet)]
;                 (println (str "Timestamp: " (.getTimestamp header)))
;                 (println (str "Original Length: " (.getOrigLength header) " bytes"))
;                 (println (str "Captured Length: " (.getCaptureLength header) " bytes"))))))


;Funkcija koja agregira tot_bytes i koja vraca counter i finalnu agregiranu vrednost
(defn aggregate
  [data]
  (reduce
    (fn [acc item]
      (let [bytes (:tot-bytes item)]
        {:tot_bytes (+ (:tot_bytes acc) bytes)
         :count       (inc (:count acc))}))
    ;Početno stanje akumulatora
    {:tot_bytes 0 :count 0}
    data))

;Funkcija za konvertovanje vrednosti na osnovu definisane jedinice ('KB, MB, GB ...)
;Kasnije modifikovati da dinamicki pronalazi da li su ('KB, MB ili GB)
(defn convert
  [unit]
  (let [base 1024]
    (case unit
      :KB (/ bytes base)
      :MB (/ bytes (* base base)) ; 1024^2
      :GB (/ bytes (* base base base)) ; 1024^3
      :TB (/ bytes (* base base base base)) ; 1024^4
      )))


(def test_data
  [{:src-ip "192.168.1.100" :protocol :tcp :tot-bytes 1024}
   {:src-ip "10.0.0.5"      :protocol :udp :tot-bytes 512}
   {:src-ip "192.168.1.100" :protocol :icmp :tot-bytes 128}
   {:src-ip "10.0.0.1"      :protocol :tcp :tot-bytes 2048}])




(defn -main
  [& args]

  (def results  (aggregate test_data))

  (println (str "Ulazni podaci: " test_data))
  (println (str "Rezultati: " results))

  (def converted-kb
    (convert (:total-bytes results) :KB))

  (println (str "Konvertovana vrednost (KB): " converted-kb)))
  ;(read-and-print-pcap-simple "src/test.pcap"))
